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
	cr := fixedBytes(32, 0xAA)
	ms := fixedBytes(48, secretByte)
	line, err := FormatLine(LabelClientRandom, cr, ms)
	if err != nil {
		panic(err)
	}
	return line
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
