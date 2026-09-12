package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UT-03.3: the pcapng path is resolved, its directory is created, and both
// are secret-grade (0700 dir, 0600 file) -- capture is a plaintext-equivalent
// secret once a keylog is embedded (AD-006).
func TestNewWriter_CreatesDirAndFileWithSecretGradePerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecar")
	path := filepath.Join(dir, "dump.pcapng")

	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())
}

// UT-03.1: the writer emits a valid SHB/IDB/EPB stream re-readable by
// gopacket, with the correct LinkType and packet bytes preserved exactly.
func TestWriter_RoundTripsPacketBytesAndLinkType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{LinkType: layers.LinkTypeRaw})
	require.NoError(t, err)

	packets := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		{0xde, 0xad, 0xbe, 0xef, 0x00},
	}
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, data := range packets {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second)}, data))
	}
	require.NoError(t, w.Close())

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	assert.Equal(t, layers.LinkTypeRaw, r.LinkType(), "link type must round-trip exactly")

	for i, want := range packets {
		data, ci, err := r.ReadPacketData()
		require.NoError(t, err, "packet %d", i)
		assert.Equal(t, want, data, "packet %d bytes must be preserved exactly", i)
		assert.True(t, ci.Timestamp.UTC().Equal(ts.Add(time.Duration(i)*time.Second)), "packet %d timestamp must round-trip", i)
	}
}

// UT-03.1/CAPTURE-02: a packet with a zero Timestamp is stamped from the
// Writer's injected Clock, tying capture timestamps to the shared source.
func TestWriter_DefaultsTimestampToInjectedClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	want := time.Date(2026, 6, 1, 8, 30, 0, 0, time.UTC)
	w, err := NewWriter(path, Options{Clock: NewManualClock(want)})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0x01}))
	require.NoError(t, w.Close())

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	_, ci, err := r.ReadPacketData()
	require.NoError(t, err)
	assert.True(t, ci.Timestamp.UTC().Equal(want), "zero timestamp must be stamped from the injected clock")
}

// UT-03.1: EmbedKeylog writes the NSS lines as a Decryption Secrets Block
// that lands in the pcapng file, and packets written on either side of it
// still read back correctly (DSB interleaving is safe).
func TestWriter_EmbedKeylog_PayloadPresentAndPacketsIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0xaa}))
	lines := []string{
		"CLIENT_RANDOM " + string(make([]byte, 64)) + " " + string(make([]byte, 96)),
	}
	require.NoError(t, w.EmbedKeylog(lines))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0xbb}))
	require.NoError(t, w.Close())

	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Contains(t, string(raw), lines[0], "embedded DSB payload must be present in the file")

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)

	data1, _, err := r.ReadPacketData()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xaa}, data1, "packet before the DSB must still read back intact")
	data2, _, err := r.ReadPacketData()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xbb}, data2, "packet after the DSB must still read back intact")
}

// Edge case: embedding no lines is a no-op, not an error.
func TestWriter_EmbedKeylog_EmptyIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	assert.NoError(t, w.EmbedKeylog(nil))
	assert.NoError(t, w.EmbedKeylog([]string{}))
}
