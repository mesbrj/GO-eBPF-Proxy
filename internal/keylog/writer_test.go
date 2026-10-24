package keylog

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleLine(secretByte byte) string {
	return formatLine(LabelClientRandom, fixedBytes(32, 0xAA), fixedBytes(48, secretByte))
}

// UT-02.4: file 0600 in dir 0700, O_APPEND, newline-terminated.
func TestWriter_ModesAndAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "sslkeylog.log")

	w, err := NewWriter(path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	line := sampleLine(0x01)
	require.NoError(t, w.Append(line))

	dirInfo, err := os.Stat(filepath.Join(dir, "sub"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Equal(t, line+"\n", string(content))
}

// UT-02.4: an NSS-malformed line is rejected and not appended.
func TestWriter_RejectsMalformedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	w, err := NewWriter(path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	err = w.Append("NOT_A_VALID_LINE too short")
	assert.ErrorIs(t, err, ErrMalformedLine)

	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Empty(t, content)
}

// UT-02.5: the same (label, client_random, secret) triple collapses to one line.
func TestWriter_DedupSameTriple(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	w, err := NewWriter(path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	line := sampleLine(0x02)
	require.NoError(t, w.Append(line))
	require.NoError(t, w.Append(line))
	require.NoError(t, w.Append(line))

	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	assert.Len(t, lines, 1, "duplicate triples must collapse to one line")
}

// AD-018: the sink sees exactly the lines the keylog file gains -- each newly
// appended line once, in order -- and never a malformed line or a duplicate,
// so the capture's DSBs mirror the keylog line for line.
func TestWriter_SinkReceivesOnlyAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	var got []string
	w, err := NewWriter(path, WithSink(func(line string) { got = append(got, line) }))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	first, second := sampleLine(0x05), sampleLine(0x06)
	require.NoError(t, w.Append(first))
	assert.ErrorIs(t, w.Append("NOT_A_VALID_LINE too short"), ErrMalformedLine)
	require.NoError(t, w.Append(first))
	require.NoError(t, w.Append(second))

	assert.Equal(t, []string{first, second}, got, "the sink must receive each appended line once, and nothing else")
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Equal(t, first+"\n"+second+"\n", string(content), "the sink must mirror the keylog file")
}

// UT-02.5: distinct handshakes (different secrets) are each appended.
func TestWriter_DistinctHandshakesAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	w, err := NewWriter(path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	require.NoError(t, w.Append(sampleLine(0x03)))
	require.NoError(t, w.Append(sampleLine(0x04)))

	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	assert.Len(t, lines, 2, "distinct handshakes must each be appended")
}

// UT-02.4: concurrent writers are serialised (no interleaved/corrupted lines);
// run with -race to catch any unsynchronised access.
func TestWriter_ConcurrentWritesSerialised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	w, err := NewWriter(path)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = w.Append(sampleLine(byte(i))) // #nosec G115 -- i < n (50), well within byte range
		}(i)
	}
	wg.Wait()

	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	assert.Len(t, lines, n, "every distinct secret must produce exactly one line")
	for _, l := range lines {
		assert.NoError(t, ValidateLine(l), "no interleaved/corrupted line")
	}
}

// C38 (AC 25): while its gate is closed, Append takes a valid new line
// without error but neither writes it to the keylog file nor hands it to the
// sink. Once the gate opens, the same line is appended and sunk.
func TestWriter_DiscardingAppendsNothingAndSinksNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	var sunk []string
	open := false
	w, err := NewWriter(path,
		WithSink(func(line string) { sunk = append(sunk, line) }),
		WithGate(func() bool { return open }),
	)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	line := sampleLine(0x07)

	require.NoError(t, w.Append(line), "a discarded valid line is not an error")
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Zero(t, info.Size(), "a closed gate must leave the keylog file's size unchanged")
	assert.Empty(t, sunk, "a closed gate must not call the sink")

	open = true
	require.NoError(t, w.Append(line))
	content, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Equal(t, line+"\n", string(content), "an open gate must append the line")
	assert.Equal(t, []string{line}, sunk, "an open gate must sink the line")
}

// C41 (AC 27): lines discarded while the gate is closed never enter the
// duplicate set, so it stays the size it had when the gate closed.
func TestWriter_DiscardingAddsNothingToDedupSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslkeylog.log")
	open := true
	w, err := NewWriter(path, WithGate(func() bool { return open }))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()
	require.NoError(t, w.Append(sampleLine(0xFF)))
	before := len(w.seen)
	require.Equal(t, 1, before, "precondition: the line appended while open is in the set")

	open = false
	for i := range 100 {
		require.NoError(t, w.Append(sampleLine(byte(i)))) // #nosec G115 -- i < 100, well within byte range
	}

	assert.Equal(t, before, len(w.seen), "100 distinct lines discarded while closed must not grow the duplicate set")
}
