package capture

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pcapng block types, per draft-tuexen-opsawg-pcapng, that the block-ordering
// assertions below recognise.
const (
	blockTypeIDB = 0x00000001
	blockTypeEPB = 0x00000006
	blockTypeDSB = 0x0000000a
	blockTypeSHB = 0x0a0d0d0a
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

// UT-03.1/CAPTURE-01 regression: a CaptureInfo whose InterfaceIndex reflects
// the OS's real ifindex (e.g. "lo"=1, "eth0"=2 in a container netns, as
// pcapgo.EthernetHandle.ReadPacketData populates it) must still be accepted
// and round-trip correctly. Before this fix, WritePacket passed a nonzero
// InterfaceIndex straight through to pcapgo.NgWriter (which only ever has
// interface 0 registered), so it always failed -- meaning any real interface
// capture silently wrote zero packets, leaving only the SHB/IDB header on
// disk (indistinguishable from an empty/broken capture).
func TestWriter_NormalizesNonZeroInterfaceIndexFromRealIfindex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	data := []byte{0x01, 0x02, 0x03}
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), InterfaceIndex: 1}, data))
	require.NoError(t, w.Close())

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	got, _, err := r.ReadPacketData()
	require.NoError(t, err, "packet with a nonzero OS ifindex must still be written and re-readable")
	assert.Equal(t, data, got)
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

// UT-03.1: EmbedKeylog's NSS lines land in the pcapng file as a Decryption
// Secrets Block, and packets written on either side of the call still read
// back correctly -- embedding never costs a packet, wherever in the session
// the keylog happens to be handed over.
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

// CAPTURE-01/CAPTURE-11 regression: the file on disk must be non-empty right
// after NewWriter (the SHB/IDB header), and must grow after each WritePacket
// -- all WITHOUT calling Close. pcapgo.NgWriter buffers internally (bufio),
// so a missing Flush left the file at 0 bytes for an entire live session
// (only visible once the sidecar was torn down), which is what a real
// end-to-end smoke test run surfaced as an apparently-empty dump.pcapng.
func TestWriter_FileVisibleOnDiskWithoutClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	sizeAfterOpen := fileSize(t, path)
	assert.Positive(t, sizeAfterOpen, "file must contain the SHB/IDB header on disk before any packet is written")

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01, 0x02, 0x03}))
	assert.Greater(t, fileSize(t, path), sizeAfterOpen, "file must grow on disk after WritePacket, without Close")
}

// CAPTURE-04/CAPTURE-11 regression: an embedded keylog is only usable if its
// Decryption Secrets Block PRECEDES the packet blocks it decrypts. pcapng
// scopes a DSB to the blocks that follow it, and tshark/Wireshark consume a
// capture strictly sequentially -- so a DSB emitted as the file's last block
// (which is what appending it at Close produced) is read only after every
// encrypted packet has already been dissected, and the advertised
// "self-decrypting capture" decrypts nothing whatsoever, even though the
// secrets are plainly present in the file.
func TestWriter_EmbedKeylog_SecretsBlockPrecedesEveryPacketBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	for _, data := range [][]byte{{0xaa}, {0xbb}, {0xcc}} {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, data))
	}
	require.NoError(t, w.EmbedKeylog([]string{nssKeylogLine}))
	require.NoError(t, w.Close())

	types := pcapngBlockTypes(t, path)
	dsb := slices.Index(types, uint32(blockTypeDSB))
	firstPacket := slices.Index(types, uint32(blockTypeEPB))
	require.NotEqual(t, -1, dsb, "capture must contain a Decryption Secrets Block; block sequence was %s", blockNames(types))
	require.NotEqual(t, -1, firstPacket, "capture must contain packet blocks; block sequence was %s", blockNames(types))
	assert.Less(t, dsb, firstPacket, "the DSB must precede the first packet block; block sequence was %s", blockNames(types))
	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB, blockTypeEPB, blockTypeEPB}, types,
		"a keylog-embedding capture must be laid out SHB -> IDB -> DSB -> packets; block sequence was %s", blockNames(types))

	assert.Contains(t, string(readFile(t, path)), nssKeylogLine, "the embedded secrets must survive the re-emission")
}

// CAPTURE-01/CAPTURE-04: re-emitting the capture to put the secrets first must
// not cost or corrupt a single packet, nor lose the link type -- the file has
// to remain a faithful capture, verified here by reading it back with a
// third-party pcapng reader rather than by inspecting how it was produced.
func TestWriter_EmbedKeylog_ReEmissionPreservesEveryPacketAndLinkType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{LinkType: layers.LinkTypeRaw})
	require.NoError(t, err)

	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	const packetCount = 64
	packets := make([][]byte, packetCount)
	for i := range packets {
		packets[i] = []byte(fmt.Sprintf("packet-%03d", i))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * time.Millisecond)}, packets[i]))
	}
	require.NoError(t, w.EmbedKeylog([]string{nssKeylogLine}))
	require.NoError(t, w.Close())

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	assert.Equal(t, layers.LinkTypeRaw, r.LinkType(), "link type must survive the re-emission")

	for i, want := range packets {
		got, ci, err := r.ReadPacketData()
		require.NoError(t, err, "packet %d must still be readable after the re-emission", i)
		assert.Equal(t, want, got, "packet %d bytes must be preserved exactly", i)
		assert.True(t, ci.Timestamp.UTC().Equal(base.Add(time.Duration(i)*time.Millisecond)), "packet %d timestamp must round-trip", i)
	}
	_, _, err = r.ReadPacketData()
	assert.Error(t, err, "the capture must hold exactly the packets that were written")
}

// AD-006: the capture is a plaintext-equivalent secret once a keylog is
// embedded, so embedding must leave the capture -- and nothing else -- in the
// directory, still at its secret-grade 0600 mode. An abandoned intermediate
// file would be an unnoticed second copy of the same secrets, and one that
// retention's own artifact bookkeeping never accounts for.
func TestWriter_EmbedKeylog_LeavesOnlyTheCaptureAtSecretGradeMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecar")
	path := filepath.Join(dir, "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01, 0x02}))
	require.NoError(t, w.EmbedKeylog([]string{nssKeylogLine}))
	require.NoError(t, w.Close())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"dump.pcapng"}, names, "embedding must leave no stray copy of the secrets behind")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the capture must stay secret-grade after embedding")
}

// Edge case: with no keylog to embed the capture is left exactly as written --
// no secrets block, and every packet still in place.
func TestWriter_Close_WithoutKeylogWritesNoSecretsBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01}))
	require.NoError(t, w.Close())

	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeEPB}, pcapngBlockTypes(t, path))
}

// nssKeylogLine is a syntactically valid but entirely fabricated NSS keylog
// line: these tests assert on block layout and packet fidelity, never on
// decryption, so no real session secret is involved.
const nssKeylogLine = "CLIENT_RANDOM " + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
	" " + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// pcapngBlockTypes returns the type of every block in the pcapng file at path,
// in file order. It walks the on-disk block stream directly -- each block is
// {type uint32, total length uint32, body, total length uint32} -- so it sees
// the file the way a sequential reader such as tshark does, independently of
// how the Writer produced it.
func pcapngBlockTypes(t *testing.T, path string) []uint32 {
	t.Helper()
	raw := readFile(t, path)

	var types []uint32
	for off := 0; off < len(raw); {
		require.LessOrEqual(t, off+8, len(raw), "truncated block header at offset %d", off)
		blockType := binary.LittleEndian.Uint32(raw[off : off+4])
		length := int(binary.LittleEndian.Uint32(raw[off+4 : off+8]))
		require.GreaterOrEqual(t, length, 12, "block at offset %d declares an impossible length %d", off, length)
		require.LessOrEqual(t, off+length, len(raw), "block at offset %d overruns the file", off)
		types = append(types, blockType)
		off += length
	}
	return types
}

// blockNames renders a block-type sequence readably, so an ordering failure
// says "SHB, IDB, EPB, DSB" rather than four hex numbers.
func blockNames(types []uint32) string {
	names := make([]string, len(types))
	for i, bt := range types {
		switch bt {
		case blockTypeSHB:
			names[i] = "SHB"
		case blockTypeIDB:
			names[i] = "IDB"
		case blockTypeEPB:
			names[i] = "EPB"
		case blockTypeDSB:
			names[i] = "DSB"
		default:
			names[i] = fmt.Sprintf("0x%08x", bt)
		}
	}
	return strings.Join(names, ", ")
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	return raw
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Size()
}
