package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	w, err := NewWriter(path, Options{Clock: newManualClock(want)})
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

// UT-03.1: a line handed to AddSecret lands in the closed pcapng file as a
// Decryption Secrets Block, and packets written on either side of it still
// read back correctly -- a secret never costs a packet, wherever in the
// session it is handed over. (Was the keylog-embedding API's test; AD-022
// removed that API, so the claim now holds for the live path, the only one
// left.)
func TestWriter_AddSecret_PayloadPresentAndPacketsIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0xaa}))
	w.AddSecret(nssKeylogLine)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0xbb}))
	require.NoError(t, w.Close())

	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Equal(t, []string{nssKeylogLine + "\n"}, secretsPayloads(raw), "the line must be in the file as a DSB payload")

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)

	data1, _, err := r.ReadPacketData()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xaa}, data1, "packet written before the secret must still read back intact")
	data2, _, err := r.ReadPacketData()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xbb}, data2, "packet written after the secret must still read back intact")
}

// Edge case: an empty line adds nothing -- no Decryption Secrets Block, live
// or at Close. (Was the keylog-embedding API's empty-is-noop test.)
func TestWriter_AddSecret_EmptyLineWritesNoSecretsBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	w.AddSecret("")
	time.Sleep(2 * flushInterval) // a stray DSB would have been drained by now
	require.NoError(t, w.Close())

	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB}, pcapngBlockTypes(t, path))
}

// liveBound is how stale the on-disk capture may be while the sidecar runs
// (AC 10): a packet waits out holdWindow, then at most one flushInterval for
// the next drain, plus scheduling slack.
const liveBound = 1500 * time.Millisecond

// CAPTURE-01/CAPTURE-11 regression: the file on disk must be non-empty right
// after NewWriter (the SHB/IDB header), and must grow after a WritePacket
// within liveBound -- all WITHOUT calling Close, and with nothing written
// after it. pcapgo.NgWriter buffers internally (bufio), so a missing Flush
// left the file at 0 bytes for an entire live session (only visible once the
// sidecar was torn down), which is what a real end-to-end smoke test run
// surfaced as an apparently-empty dump.pcapng.
func TestWriter_FileVisibleOnDiskWithoutClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	sizeAfterOpen := fileSize(t, path)
	assert.Positive(t, sizeAfterOpen, "file must contain the SHB/IDB header on disk before any packet is written")

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01, 0x02, 0x03}))
	assert.Eventually(t, func() bool { return fileSize(t, path) > sizeAfterOpen }, liveBound, 20*time.Millisecond,
		"a lone packet must reach the file on disk within %s, without Close or any later packet", liveBound)
}

// AC 10: the tail of a burst must not wait for the next packet. Packets that
// arrive within one flush interval of each other used to sit in the buffer
// until something else arrived, for as long as the interface stayed quiet.
func TestWriter_BurstTailReachesDiskWithoutLaterTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	for i := range 3 {
		if i > 0 {
			time.Sleep(10 * time.Millisecond)
		}
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{byte(i)}))
	}
	assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 3 }, liveBound, 20*time.Millisecond,
		"all three packets of the burst must be on disk within %s of the last one, without Close", liveBound)
}

// AC 5 (AD-018): a secret that arrives while a packet is still inside the hold
// window is written ahead of it -- in the file on disk, before Close -- since
// tshark decrypts a TLS 1.3 session only when its secrets precede the
// session's ServerHello, which is captured before the client can derive them.
func TestWriter_LiveSecretPrecedesPacketsStillHeld(t *testing.T) {
	for _, age := range []time.Duration{0, 500 * time.Millisecond, 990 * time.Millisecond} {
		t.Run(age.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dump.pcapng")
			clock := newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
			w, err := NewWriter(path, Options{Clock: clock})
			require.NoError(t, err)
			defer func() { _ = w.Close() }()

			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xaa}))
			clock.Advance(age)
			w.AddSecret(nssKeylogLine)

			assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeDSB) == 1 }, liveBound, 20*time.Millisecond,
				"the secret must reach the file on disk without Close")
			assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB}, blockTypes(readFile(t, path)),
				"a packet held for %s must not be written before the secret that arrived after it", age)

			clock.Advance(holdWindow)
			assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 1 }, liveBound, 20*time.Millisecond,
				"the packet must be written once it has been held for %s", holdWindow)
			assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB}, blockTypes(readFile(t, path)),
				"the live DSB must precede the packet it may decrypt")
			assert.Equal(t, []string{nssKeylogLine + "\n"}, secretsPayloads(readFile(t, path)))
		})
	}
}

// AC 5: a live DSB carries exactly the lines handed over since the last
// drain, newline-terminated, and a drained line is never written again.
// Duplicates never reach the Writer: keylog.Writer drops them before its sink
// (feature 07 C35), so the Writer keeps no set of the lines it has seen.
func TestWriter_LiveSecretsWrittenOnceEach(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Clock: newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	first, second := keylogLine(1), keylogLine(2)
	w.AddSecret(first)
	assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeDSB) == 1 }, liveBound, 20*time.Millisecond)
	w.AddSecret(second)
	assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeDSB) == 2 }, liveBound, 20*time.Millisecond)

	time.Sleep(2 * flushInterval) // a stray third DSB would have been drained by now
	assert.Equal(t, []string{first + "\n", second + "\n"}, secretsPayloads(readFile(t, path)),
		"each live DSB must hold exactly the new lines, each once")
}

// Landing door 1 (AD-018): when one write releases pending secrets and packets
// together, the secrets go first -- any of those packets may be the very
// ServerHello the secrets decrypt. Two writes can do that: the periodic drain,
// when a secret arrives just before its packet's hold window ends, and the
// write the 32 MiB cap forces early. In each case the secret and the packet's
// release are handed over back to back, so the next write sees both; a drain
// slipping in between would write the secret alone first, which still meets
// the order asserted here.
func TestWriter_PendingSecretsPrecedePacketsReleasedWithThem(t *testing.T) {
	t.Run("periodic drain", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		clock := newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
		w, err := NewWriter(path, Options{Clock: clock})
		require.NoError(t, err)
		defer func() { _ = w.Close() }()

		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xaa}))
		w.AddSecret(nssKeylogLine)
		clock.Advance(holdWindow)

		assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 1 }, liveBound, 20*time.Millisecond)
		assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB}, blockTypes(readFile(t, path)),
			"a drain releasing a secret and a packet together must write the secret first")
	})
	t.Run("cap-forced write", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		w, err := NewWriter(path, Options{Clock: newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))})
		require.NoError(t, err)
		defer func() { _ = w.Close() }()

		const size = 64 << 10
		for range maxHeldBytes / size {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, make([]byte, size)))
		}
		w.AddSecret(nssKeylogLine)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xff}))

		assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 1 }, liveBound, 20*time.Millisecond)
		assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB}, blockTypes(readFile(t, path)),
			"a write forced by the cap must write the pending secret before the packet it releases")
	})
}

// AC 7: the hold queue is bounded. Holding exactly maxHeldBytes writes
// nothing early; one byte more writes the oldest packets until the held
// total is back within the cap -- here exactly one, the oldest.
func TestWriter_HoldCapWritesOldestPacketsFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Clock: newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	const size = 64 << 10
	for i := range maxHeldBytes / size {
		data := make([]byte, size)
		data[0] = byte(i) // packet 0 is the oldest
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, data))
	}
	time.Sleep(2 * flushInterval)
	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB}, blockTypes(readFile(t, path)),
		"holding exactly %d bytes must not write any packet before its hold window ends", maxHeldBytes)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xff}))
	assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 1 }, liveBound, 20*time.Millisecond,
		"one byte past the cap must write the oldest packet at once")
	time.Sleep(2 * flushInterval)
	packets := packetPayloads(readFile(t, path))
	require.Len(t, packets, 1, "only as many packets as it takes to get back within the cap may be written early")
	assert.Equal(t, byte(0), packets[0][0], "the packet written early must be the oldest")
	assert.Len(t, packets[0], size)
}

// AC 8: Close writes every packet handed to WritePacket, in order, including
// the ones still inside the hold window.
func TestWriter_CloseWritesEveryHeldPacket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	var want [][]byte
	for i := range 5 {
		data := []byte(fmt.Sprintf("held-%d", i))
		want = append(want, data)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, data))
	}
	require.NoError(t, w.Close())

	assert.Equal(t, want, readPackets(t, path), "Close must write every held packet, in order")
}

// Door 3 (feature 07, AD-022): after Close the capture keeps its live layout
// -- each DSB where the drain wrote it, ahead of the packets held when its
// lines arrived -- and each line once. Close drains the tail the same way.
// (Supersedes feature 06 C11, which required the single leading DSB of
// AD-014's re-emission.)
func TestWriter_CloseKeepsTheLiveLayoutWithEachLineOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	clock := newManualClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	w, err := NewWriter(path, Options{Clock: clock})
	require.NoError(t, err)

	first, second := keylogLine(1), keylogLine(2)
	w.AddSecret(first)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xaa}))
	clock.Advance(holdWindow)
	require.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 1 }, liveBound, 20*time.Millisecond,
		"precondition: the first secret and packet are written live")

	w.AddSecret(second)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xbb}))
	require.NoError(t, w.Close())

	raw := readFile(t, path)
	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB, blockTypeDSB, blockTypeEPB}, blockTypes(raw),
		"a closed capture must keep the live layout; block sequence was %s", blockNames(blockTypes(raw)))
	assert.Equal(t, []string{first + "\n", second + "\n"}, secretsPayloads(raw), "each DSB must hold the lines of its own drain, each once")
	assert.Equal(t, [][]byte{{0xaa}, {0xbb}}, packetPayloads(raw))
}

// C32 (AC 21, door 3): Close never rewrites the capture. The closed file is
// the very inode written live, it begins with exactly the bytes that were on
// disk before Close, it still holds every live DSB, and nothing else -- no
// temporary copy -- is left in the directory.
func TestWriter_CloseNeverRewritesTheFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecar")
	path := filepath.Join(dir, "dump.pcapng")
	clock := newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	w, err := NewWriter(path, Options{Clock: clock})
	require.NoError(t, err)

	lines := []string{keylogLine(1), keylogLine(2), keylogLine(3)}
	for i, line := range lines[:2] {
		w.AddSecret(line)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{byte(0xa0 + i), 0x01}))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{byte(0xa0 + i), 0x02}))
		clock.Advance(holdWindow)
		require.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 2*(i+1) }, liveBound, 20*time.Millisecond,
			"precondition: drain %d writes its secret and packets live", i+1)
	}
	// A tail for Close to drain: a secret and a packet still held.
	w.AddSecret(lines[2])
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, []byte{0xa2, 0x01}))

	live := readFile(t, path)
	liveInfo, err := os.Stat(path)
	require.NoError(t, err)
	require.GreaterOrEqual(t, countBlocks(live, blockTypeDSB), 2, "precondition: both live DSBs are on disk before Close")

	require.NoError(t, w.Close())

	closed := readFile(t, path)
	require.GreaterOrEqual(t, len(closed), len(live))
	assert.Equal(t, live, closed[:len(live)], "the closed file must begin with exactly the bytes on disk before Close")
	assert.Equal(t, []string{lines[0] + "\n", lines[1] + "\n", lines[2] + "\n"}, secretsPayloads(closed),
		"the live DSBs must survive Close, followed by the one Close drained")
	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB, blockTypeEPB, blockTypeDSB, blockTypeEPB, blockTypeEPB, blockTypeDSB, blockTypeEPB},
		blockTypes(closed), "block sequence was %s", blockNames(blockTypes(closed)))

	closedInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, os.SameFile(liveInfo, closedInfo), "Close must not replace the capture with another file")
	assert.Equal(t, []string{"dump.pcapng"}, dirNames(t, dir), "Close must leave no other file beside the capture")
}

// C33 (AC 21): Close never reopens the capture by name, so a capture unlinked
// while live -- the reproduced retention eviction -- still closes cleanly,
// and Close does not bring it back.
func TestWriter_CloseSucceedsAfterFileUnlinked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01}))
	w.AddSecret(nssKeylogLine)
	require.NoError(t, os.Remove(path))

	assert.NoError(t, w.Close(), "Close must succeed on a capture unlinked while live")
	assert.Empty(t, dirNames(t, dir), "Close must not recreate the capture or leave any other file")
}

// C37 (AC 24): the Writer keeps a keylog line only until the drain that writes
// it. Checked over the struct by reflection, so a field added later to keep
// lines around -- a slice of every line, a dedup set -- fails here too.
func TestWriter_KeepsNoLineAfterItsDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Clock: newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))})
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	const lines = 100
	for n := range lines {
		w.AddSecret(keylogLine(n))
	}
	require.Eventually(t, func() bool { return len(payloadLines(secretsPayloads(readFile(t, path)))) == lines }, liveBound, 20*time.Millisecond,
		"precondition: every line is drained into the file")

	w.mu.Lock()
	defer w.mu.Unlock()
	v := reflect.ValueOf(w).Elem()
	for i := range v.NumField() {
		field, f := v.Type().Field(i), v.Field(i)
		switch {
		case f.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String:
			assert.Zero(t, f.Len(), "[]string field %s still holds lines after their drain", field.Name)
		case f.Kind() == reflect.Map && field.Type.Key().Kind() == reflect.String:
			assert.Zero(t, f.Len(), "map field %s still holds lines after their drain", field.Name)
		}
	}
}

// C35 (AC 22), AC 8: the capture goroutine, many keylog connections and the
// periodic drain all reach the Writer at once in the sidecar. Run under
// -race, this must report no race, and the closed capture must hold every
// packet in order, and each line in exactly one of its live DSBs.
func TestWriter_ConcurrentPacketsAndSecretsAreRaceFree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	const packets, senders, linesPerSender = 400, 8, 8
	var wg sync.WaitGroup
	wg.Add(1 + senders)
	go func() {
		defer wg.Done()
		for i := range packets {
			_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte(fmt.Sprintf("pkt-%03d", i)))
			if i%50 == 0 {
				time.Sleep(flushInterval / 2) // let drains interleave with the writes
			}
		}
	}()
	for s := range senders {
		go func() {
			defer wg.Done()
			for l := range linesPerSender {
				w.AddSecret(keylogLine(s*linesPerSender + l))
			}
		}()
	}
	wg.Wait()
	require.NoError(t, w.Close())

	got := readPackets(t, path)
	require.Len(t, got, packets)
	for i, data := range got {
		assert.Equal(t, fmt.Sprintf("pkt-%03d", i), string(data), "packet %d out of order", i)
	}
	payloads := secretsPayloads(readFile(t, path))
	require.NotEmpty(t, payloads)
	dsbsHolding := make(map[string]int)
	for _, payload := range payloads {
		for _, line := range payloadLines([]string{payload}) {
			dsbsHolding[line]++
		}
	}
	assert.Len(t, dsbsHolding, senders*linesPerSender, "the DSBs must hold exactly the lines handed over")
	for n := range senders * linesPerSender {
		assert.Equal(t, 1, dsbsHolding[keylogLine(n)], "line %d must appear in exactly one DSB, once", n)
	}
}

// CAPTURE-04/CAPTURE-11 regression: an embedded secret is only usable if its
// Decryption Secrets Block PRECEDES the packet blocks it decrypts. pcapng
// scopes a DSB to the blocks that follow it, and tshark/Wireshark consume a
// capture strictly sequentially -- so a DSB emitted as the file's last block
// (which is what appending it at Close once produced) is read only after
// every encrypted packet has already been dissected, and the advertised
// "self-decrypting capture" decrypts nothing whatsoever, even though the
// secrets are plainly present in the file. Since AD-022 the live path is the
// only one that places secrets: a line handed over while packets are still
// held must land ahead of all of them in the closed capture. (Was AD-014's
// keylog-embedding test, which relied on Close's re-emission.)
func TestWriter_SecretsBlockPrecedesEveryPacketHeldWhenItArrived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Clock: newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))})
	require.NoError(t, err)

	for _, data := range [][]byte{{0xaa}, {0xbb}, {0xcc}} {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, data))
	}
	w.AddSecret(nssKeylogLine)
	require.NoError(t, w.Close())

	types := pcapngBlockTypes(t, path)
	dsb := slices.Index(types, uint32(blockTypeDSB))
	firstPacket := slices.Index(types, uint32(blockTypeEPB))
	require.NotEqual(t, -1, dsb, "capture must contain a Decryption Secrets Block; block sequence was %s", blockNames(types))
	require.NotEqual(t, -1, firstPacket, "capture must contain packet blocks; block sequence was %s", blockNames(types))
	assert.Less(t, dsb, firstPacket, "the DSB must precede the first packet block; block sequence was %s", blockNames(types))
	assert.Equal(t, []uint32{blockTypeSHB, blockTypeIDB, blockTypeDSB, blockTypeEPB, blockTypeEPB, blockTypeEPB}, types,
		"a secret handed over while every packet is held must be laid out SHB -> IDB -> DSB -> packets; block sequence was %s", blockNames(types))

	assert.Equal(t, []string{nssKeylogLine + "\n"}, secretsPayloads(readFile(t, path)), "the secret must be in the closed capture")
}

// CAPTURE-01/CAPTURE-04: interleaving live DSBs with the packets must not cost
// or corrupt a single packet, nor lose the link type -- the closed file has to
// remain a faithful capture, verified here by reading it back with a
// third-party pcapng reader rather than by inspecting how it was produced.
// (Was the re-emission's fidelity test; AD-022 removed the re-emission, so
// the claim now holds for the live path that writes DSBs between packets.)
func TestWriter_LiveSecretsPreserveEveryPacketAndLinkType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	clock := newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
	w, err := NewWriter(path, Options{LinkType: layers.LinkTypeRaw, Clock: clock})
	require.NoError(t, err)

	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	const packetCount = 64
	packets := make([][]byte, packetCount)
	for i := range packets {
		packets[i] = []byte(fmt.Sprintf("packet-%03d", i))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * time.Millisecond)}, packets[i]))
		if i == packetCount/2 {
			// Write the first half live, behind one secret, so the second
			// secret's DSB lands between packet blocks.
			w.AddSecret(keylogLine(1))
			clock.Advance(holdWindow)
			require.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == i+1 }, liveBound, 20*time.Millisecond)
		}
	}
	w.AddSecret(keylogLine(2))
	require.NoError(t, w.Close())
	require.Equal(t, 2, countBlocks(readFile(t, path), blockTypeDSB), "precondition: two DSBs among the packets")

	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	assert.Equal(t, layers.LinkTypeRaw, r.LinkType(), "link type must survive live DSBs")

	for i, want := range packets {
		got, ci, err := r.ReadPacketData()
		require.NoError(t, err, "packet %d must still be readable among the live DSBs", i)
		assert.Equal(t, want, got, "packet %d bytes must be preserved exactly", i)
		assert.True(t, ci.Timestamp.UTC().Equal(base.Add(time.Duration(i)*time.Millisecond)), "packet %d timestamp must round-trip", i)
	}
	_, _, err = r.ReadPacketData()
	assert.Error(t, err, "the capture must hold exactly the packets that were written")
}

// AD-006: the capture is a plaintext-equivalent secret once it holds a DSB,
// so closing it must leave the capture -- and nothing else -- in the
// directory, still at its secret-grade 0600 mode. An intermediate file would
// be an unnoticed second copy of the same secrets, and one that retention's
// own artifact bookkeeping never accounts for. (Was the keylog-embedding
// API's test.)
func TestWriter_CloseLeavesOnlyTheCaptureAtSecretGradeMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sidecar")
	path := filepath.Join(dir, "dump.pcapng")
	w, err := NewWriter(path, Options{})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, []byte{0x01, 0x02}))
	w.AddSecret(nssKeylogLine)
	require.NoError(t, w.Close())

	assert.Equal(t, []string{"dump.pcapng"}, dirNames(t, dir), "Close must leave no stray copy of the secrets behind")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the capture must stay secret-grade after Close")
	assert.Equal(t, 1, countBlocks(readFile(t, path), blockTypeDSB), "precondition: the capture holds the secret")
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

// The fixed sizes the room tests count in: an Ethernet capture's header (its
// SHB and IDB), and the Enhanced Packet Block of a 100 B packet.
const (
	headerBytes = 124
	epb100Bytes = 132
)

// packet100 returns a 100 B packet filled with b, so each one is told apart.
func packet100(b byte) []byte { return bytes.Repeat([]byte{b}, 100) }

// lineDSBBytes is the size of a Decryption Secrets Block holding line alone:
// 20 B of block framing plus the newline-terminated line padded to 4 B.
func lineDSBBytes(line string) int64 { return 20 + (int64(len(line))+1+3)&^3 }

// C1 (AC 1, AC 2): the room is a hard bound on the file. With room for the
// header and exactly three packets, the fourth stops capture and nothing after
// it is written; one byte less and only two fit.
func TestWriter_StopsBeforeFilePassesItsRoom(t *testing.T) {
	require.Equal(t, int64(headerBytes), HeaderSize(Options{}), "precondition: an Ethernet capture's header is 124 B")

	t.Run("520 B room", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		w, err := NewWriter(path, Options{Room: headerBytes + 3*epb100Bytes})
		require.NoError(t, err)
		for i := range 3 {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(byte(i))), "packet %d fits the room", i)
		}
		assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(3)), ErrStopped, "the fourth packet must stop capture")
		assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(4)), ErrStopped, "a packet after the stop must not be written")
		require.NoError(t, w.Close())

		raw := readFile(t, path)
		assert.Len(t, raw, 520, "the closed file must fill its room exactly")
		assert.Equal(t, [][]byte{packet100(0), packet100(1), packet100(2)}, packetPayloads(raw))
	})
	t.Run("519 B room", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		w, err := NewWriter(path, Options{Room: headerBytes + 3*epb100Bytes - 1})
		require.NoError(t, err)
		for i := range 2 {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(byte(i))), "packet %d fits the room", i)
		}
		assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(2)), ErrStopped, "one byte short, the third packet must stop capture")
		require.NoError(t, w.Close())

		raw := readFile(t, path)
		assert.Len(t, raw, headerBytes+2*epb100Bytes)
		assert.Equal(t, [][]byte{packet100(0), packet100(1)}, packetPayloads(raw))
	})
}

// C2 (AC 1): what is admitted counts at once, whether or not it is on disk
// yet. Packets in the hold window count, and so does a pending secret.
func TestWriter_HeldPacketsAndPendingSecretsCountTowardRoom(t *testing.T) {
	t.Run("held packets", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		clock := newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))
		w, err := NewWriter(path, Options{Room: headerBytes + 3*epb100Bytes, Clock: clock})
		require.NoError(t, err)
		for i := range 3 {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, packet100(byte(i))))
		}
		assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{}, packet100(3)), ErrStopped,
			"three held packets fill a 520 B room, so the fourth must be refused")
		assert.Equal(t, int64(headerBytes), fileSize(t, path), "the clock never moved, so the three packets are still held: only the header is on disk")
		require.NoError(t, w.Close())
		assert.Len(t, readPackets(t, path), 3)
	})
	t.Run("pending secret", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dump.pcapng")
		w, err := NewWriter(path, Options{Room: headerBytes + lineDSBBytes(nssKeylogLine) + 2*epb100Bytes,
			Clock: newManualClock(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC))})
		require.NoError(t, err)
		w.AddSecret(nssKeylogLine)
		for i := range 2 {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{}, packet100(byte(i))))
		}
		assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{}, packet100(2)), ErrStopped,
			"the secret's block and two packets fill the room, so the third packet must be refused")
		require.NoError(t, w.Close())

		raw := readFile(t, path)
		assert.Equal(t, []string{nssKeylogLine + "\n"}, secretsPayloads(raw))
		assert.Equal(t, [][]byte{packet100(0), packet100(1)}, packetPayloads(raw))
	})
}

// C3 (AC 2): a keylog line stops capture just as a packet does, when its
// Decryption Secrets Block does not fit the room left. Neither the line nor a
// packet after it reaches the file.
func TestWriter_SecretThatDoesNotFitStopsCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Room: headerBytes + epb100Bytes + lineDSBBytes(nssKeylogLine) - 1})
	require.NoError(t, err)

	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(0)))
	w.AddSecret(nssKeylogLine)
	assert.Equal(t, StateStoppedMaxBytes, w.State(), "a line whose block does not fit must stop capture")
	assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(1)), ErrStopped)
	require.NoError(t, w.Close())

	raw := readFile(t, path)
	assert.Empty(t, secretsPayloads(raw), "the line that stopped capture must be in no DSB")
	assert.Equal(t, [][]byte{packet100(0)}, packetPayloads(raw), "only the packet admitted before the stop may be in the file")
}

// C4 (AC 3): a stop drops what comes after it, never what was admitted before
// it. Packets still held at the stop reach the file live, once their hold
// window passes, and the file is kept.
func TestWriter_StopStillWritesWhatItAdmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Room: headerBytes + 3*epb100Bytes})
	require.NoError(t, err)

	for i := range 3 {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(byte(i))))
	}
	require.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(3)), ErrStopped)
	assert.Eventually(t, func() bool { return countBlocks(readFile(t, path), blockTypeEPB) == 3 }, liveBound, 20*time.Millisecond,
		"the three packets held at the stop must reach the file within %s, without Close", liveBound)

	require.NoError(t, w.Close())
	assert.FileExists(t, path, "a stopped capture must be kept")
	assert.Equal(t, [][]byte{packet100(0), packet100(1), packet100(2)}, packetPayloads(readFile(t, path)))
}

// C5 (AC 8): while capture is active, a grown room admits what the old one
// could not.
func TestWriter_GrownRoomAdmitsMore(t *testing.T) {
	const room = headerBytes + epb100Bytes - 1 // one byte short of a 100 B packet's block
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	w, err := NewWriter(path, Options{Room: room})
	require.NoError(t, err)

	w.SetRoom(room + 1000)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(0)), "the grown room must admit the packet")
	assert.Equal(t, StateActive, w.State())
	require.NoError(t, w.Close())
	assert.Equal(t, [][]byte{packet100(0)}, packetPayloads(readFile(t, path)))
}

// C6 (AC 9): a stop is for good. A room grown afterwards admits neither a
// packet nor a line, and no second capture file appears.
func TestWriter_StoppedStaysStoppedWhenRoomGrows(t *testing.T) {
	const room = headerBytes + epb100Bytes - 1
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.pcapng")
	w, err := NewWriter(path, Options{Room: room})
	require.NoError(t, err)
	require.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(0)), ErrStopped)

	w.SetRoom(room + 1<<20)
	assert.ErrorIs(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(1)), ErrStopped, "a stopped capture must not admit a packet")
	w.AddSecret(nssKeylogLine)
	assert.Equal(t, StateStoppedMaxBytes, w.State(), "a stopped capture must stay stopped")
	require.NoError(t, w.Close())

	raw := readFile(t, path)
	assert.Empty(t, packetPayloads(raw), "no packet may be written after the stop")
	assert.Empty(t, secretsPayloads(raw), "no line may be written after the stop")
	assert.Equal(t, []string{"dump.pcapng"}, dirNames(t, dir), "no second capture file may appear")
}

// C7 (AC 1, AC 4): packets, secrets and room updates race in the sidecar. Under
// -race there must be no data race, the stop must be notified exactly once,
// and the closed file must stay within the last room handed over.
func TestWriter_ConcurrentLimitStopIsRaceFreeAndHappensOnce(t *testing.T) {
	const initialRoom = 4 << 10
	path := filepath.Join(t.TempDir(), "dump.pcapng")
	var stops atomic.Int32
	w, err := NewWriter(path, Options{Room: initialRoom, OnStop: func(Stop) { stops.Add(1) }})
	require.NoError(t, err)

	var finalRoom atomic.Int64
	finalRoom.Store(initialRoom)
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Go(func() {
			for i := range 200 {
				_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, packet100(byte(i)))
			}
		})
		wg.Go(func() {
			for l := range 50 {
				w.AddSecret(keylogLine(g*50 + l))
			}
		})
	}
	wg.Go(func() {
		for i := 1; i <= 10; i++ {
			room := int64(initialRoom + i*1024)
			w.SetRoom(room)
			finalRoom.Store(room)
			time.Sleep(time.Millisecond)
		}
	})
	wg.Wait()
	require.NoError(t, w.Close())

	require.Equal(t, StateStoppedMaxBytes, w.State(), "precondition: 800 packets of 132 B overrun every room handed over")
	assert.Equal(t, int32(1), stops.Load(), "the stop must be notified exactly once")
	assert.LessOrEqual(t, fileSize(t, path), finalRoom.Load(), "the closed file must not exceed the final room")
}

// runStart is the Unix second the run-capture tests start at.
const runStart = 1761300000

// runOpts returns Options whose clock reads runStart.
func runOpts() Options { return Options{Clock: newManualClock(time.Unix(runStart, 0))} }

// C21 (AC 14, door 1): each run's file is the template's directory and stem,
// its start second, and the template's extension, created 0600.
func TestRunCapture_NamedFromTemplateAndStartSecond(t *testing.T) {
	for _, tc := range []struct{ template, want string }{
		{"dump.pcapng", "dump-1761300000.pcapng"},
		{"cap", "cap-1761300000"},
		{"a.b.pcapng", "a.b-1761300000.pcapng"},
	} {
		t.Run(tc.template, func(t *testing.T) {
			dir := t.TempDir()
			w, err := CreateRunCapture(filepath.Join(dir, tc.template), runOpts())
			require.NoError(t, err)
			require.NoError(t, w.Close())

			want := filepath.Join(dir, tc.want)
			assert.Equal(t, want, w.Path())
			info, err := os.Lstat(want)
			require.NoError(t, err)
			assert.True(t, info.Mode().IsRegular())
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			assert.Equal(t, []string{tc.want}, dirNames(t, dir), "the run must create exactly its own file")
		})
	}
}

// C22 (AC 15, door 1): a taken name is skipped, whatever holds it -- a file, a
// symlink to one, a dangling symlink or a directory -- for the lowest free
// suffix. What holds it is left exactly as it was: never written through,
// never followed, and a dangling symlink's target is never created.
func TestRunCapture_CollisionTakesLowestFreeSuffix(t *testing.T) {
	// Each kind plants an entry at path and returns a check that it is
	// unchanged.
	kinds := []struct {
		name  string
		plant func(t *testing.T, path string) func(t *testing.T)
	}{
		{"regular file", func(t *testing.T, path string) func(t *testing.T) {
			require.NoError(t, os.WriteFile(path, []byte("kept "+path), 0o600))
			return func(t *testing.T) { assert.Equal(t, []byte("kept "+path), readFile(t, path)) }
		}},
		{"symlink to a file", func(t *testing.T, path string) func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "target")
			require.NoError(t, os.WriteFile(target, []byte("target bytes"), 0o600))
			require.NoError(t, os.Symlink(target, path))
			return func(t *testing.T) {
				got, err := os.Readlink(path)
				require.NoError(t, err)
				assert.Equal(t, target, got)
				assert.Equal(t, []byte("target bytes"), readFile(t, target))
			}
		}},
		{"dangling symlink", func(t *testing.T, path string) func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "missing")
			require.NoError(t, os.Symlink(target, path))
			return func(t *testing.T) {
				got, err := os.Readlink(path)
				require.NoError(t, err)
				assert.Equal(t, target, got)
				assert.NoFileExists(t, target, "a dangling symlink's target must never be created")
			}
		}},
		{"directory", func(t *testing.T, path string) func(t *testing.T) {
			require.NoError(t, os.Mkdir(path, 0o700))
			return func(t *testing.T) { assert.Empty(t, dirNames(t, path)) }
		}},
	}
	for _, kind := range kinds {
		for taken, want := range []string{"dump-1761300000-1.pcapng", "dump-1761300000-2.pcapng"} {
			t.Run(fmt.Sprintf("%s/%d taken", kind.name, taken+1), func(t *testing.T) {
				dir := t.TempDir()
				var checks []func(t *testing.T)
				for _, name := range []string{"dump-1761300000.pcapng", "dump-1761300000-1.pcapng"}[:taken+1] {
					checks = append(checks, kind.plant(t, filepath.Join(dir, name)))
				}

				w, err := CreateRunCapture(filepath.Join(dir, "dump.pcapng"), runOpts())
				require.NoError(t, err)
				require.NoError(t, w.Close())

				assert.Equal(t, filepath.Join(dir, want), w.Path())
				for _, check := range checks {
					check(t)
				}
			})
		}
	}
}

// C23 (AC 16, door 1): suffix 999 is the last one tried. Past it, creation
// fails naming the capture directory, and creates nothing.
func TestRunCapture_GivesUpAfterSuffix999(t *testing.T) {
	// takeNames plants an empty file at the base name and at suffixes 1 to last.
	takeNames := func(t *testing.T, dir string, last int) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "dump-1761300000.pcapng"), nil, 0o600))
		for n := 1; n <= last; n++ {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "dump-1761300000-"+strconv.Itoa(n)+".pcapng"), nil, 0o600))
		}
	}

	t.Run("suffix 999 free", func(t *testing.T) {
		dir := t.TempDir()
		takeNames(t, dir, 998)
		w, err := CreateRunCapture(filepath.Join(dir, "dump.pcapng"), runOpts())
		require.NoError(t, err)
		require.NoError(t, w.Close())
		assert.Equal(t, filepath.Join(dir, "dump-1761300000-999.pcapng"), w.Path())
	})
	t.Run("suffixes 1 to 999 taken", func(t *testing.T) {
		dir := t.TempDir()
		takeNames(t, dir, 999)
		before := dirNames(t, dir)

		w, err := CreateRunCapture(filepath.Join(dir, "dump.pcapng"), runOpts())
		require.Error(t, err)
		assert.Nil(t, w)
		assert.Contains(t, err.Error(), dir, "the error must name the capture directory")
		assert.Equal(t, before, dirNames(t, dir), "no file may be created")
	})
}

// C24 (door 1): an open error other than a taken name fails creation at once,
// naming the file it tried.
func TestRunCapture_OtherOpenErrorFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the open cannot be made to fail this way")
	}
	dir := filepath.Join(t.TempDir(), "sidecar")
	require.NoError(t, os.Mkdir(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restores a test directory so t.TempDir can remove it

	w, err := CreateRunCapture(filepath.Join(dir, "dump.pcapng"), runOpts())
	require.Error(t, err)
	assert.Nil(t, w)
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.Contains(t, err.Error(), "dump-1761300000.pcapng", "the error must name the file it tried to create")
	assert.Empty(t, dirNames(t, dir))
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

// keylogLine returns a distinct, fabricated NSS keylog line for n.
func keylogLine(n int) string {
	return fmt.Sprintf("CLIENT_RANDOM %064x %096x", n, n)
}

// pcapngBlock is one complete block of a pcapng file: its type and body.
type pcapngBlock struct {
	typ  uint32
	body []byte
}

// completeBlocks walks raw's block stream and returns every complete block,
// stopping silently at a trailing block that is still being written: a live
// capture can be read mid-flush, which pcapngBlockTypes would reject.
func completeBlocks(raw []byte) []pcapngBlock {
	var blocks []pcapngBlock
	for off := 0; off+8 <= len(raw); {
		length := int(binary.LittleEndian.Uint32(raw[off+4 : off+8]))
		if length < 12 || off+length > len(raw) {
			break
		}
		blocks = append(blocks, pcapngBlock{typ: binary.LittleEndian.Uint32(raw[off : off+4]), body: raw[off+8 : off+length-4]})
		off += length
	}
	return blocks
}

func blockTypes(raw []byte) []uint32 {
	var types []uint32
	for _, b := range completeBlocks(raw) {
		types = append(types, b.typ)
	}
	return types
}

func countBlocks(raw []byte, typ uint32) int {
	n := 0
	for _, b := range completeBlocks(raw) {
		if b.typ == typ {
			n++
		}
	}
	return n
}

// secretsPayloads returns the payload of every Decryption Secrets Block in
// raw, in file order. A DSB body is {secrets type, secrets length, data}.
func secretsPayloads(raw []byte) []string {
	var payloads []string
	for _, b := range completeBlocks(raw) {
		if b.typ == blockTypeDSB {
			n := binary.LittleEndian.Uint32(b.body[4:8])
			payloads = append(payloads, string(b.body[8:8+n]))
		}
	}
	return payloads
}

// packetPayloads returns the captured bytes of every Enhanced Packet Block in
// raw, in file order. An EPB body is {interface id, timestamp high, timestamp
// low, captured length, original length, data}.
func packetPayloads(raw []byte) [][]byte {
	var packets [][]byte
	for _, b := range completeBlocks(raw) {
		if b.typ == blockTypeEPB {
			n := binary.LittleEndian.Uint32(b.body[12:16])
			packets = append(packets, b.body[20:20+n])
		}
	}
	return packets
}

// readPackets reads every packet of the capture at path through gopacket's
// own pcapng reader -- a third-party reader, independent of the Writer.
func readPackets(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)
	var packets [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return packets
		}
		require.NoError(t, err)
		packets = append(packets, data)
	}
}

// payloadLines splits DSB payloads into their newline-terminated NSS lines,
// in file order.
func payloadLines(payloads []string) []string {
	var lines []string
	for _, p := range payloads {
		lines = append(lines, strings.Split(strings.TrimSuffix(p, "\n"), "\n")...)
	}
	return lines
}

// dirNames lists the names of every entry in dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
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
