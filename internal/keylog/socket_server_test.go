package keylog

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// wellFormedLine returns a valid CLIENT_RANDOM NSS line (32-byte
// client_random, 48-byte master secret), matching writer_test.go's fixtures.
func wellFormedLine() string {
	return "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48)
}

// newTestSocketServer starts a SocketServer under t.TempDir() and returns it
// plus its socket path, running Run() in the background and closing it on
// cleanup. The socket lives in a not-yet-created "sock" subdirectory so that
// NewSocketServer's own os.MkdirAll(dir, 0o711) is the call that creates it
// (MkdirAll is a no-op on an already-existing directory, so reusing
// t.TempDir() directly would leave its actual mode -- e.g. 0775 on some
// systems -- unchanged and trip the permission guard).
func newTestSocketServer(t *testing.T, opts ...SocketServerOption) (*SocketServer, string, string) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock", "keylog.sock")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	s, err := NewSocketServer(SocketServerConfig{SocketPath: sockPath, KeylogPath: keylogPath}, opts...)
	require.NoError(t, err)
	go func() { _ = s.Run() }()
	t.Cleanup(func() { _ = s.Close() })
	return s, sockPath, keylogPath
}

// waitForKeylogLineCount polls path until it has exactly want non-empty
// lines or timeout elapses, then returns the final content.
func waitForKeylogLineCount(t *testing.T, path string, want int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
		if err == nil {
			last = string(data)
			lines := 0
			for _, l := range strings.Split(strings.TrimRight(last, "\n"), "\n") {
				if l != "" {
					lines++
				}
			}
			if lines == want {
				return last
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d line(s) in %q; last content: %q", want, path, last)
	return ""
}

// UT-02.5: well-formed lines sent over a real unix socket connection are
// deduplicated and appended via the existing Writer.Append pipeline.
func TestSocketServer_WellFormedLines_DedupedAndAppended(t *testing.T) {
	_, sockPath, keylogPath := newTestSocketServer(t)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)

	line := wellFormedLine()
	_, err = conn.Write([]byte(line + "\n" + line + "\n")) // duplicate: dedup must collapse to one
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	got := waitForKeylogLineCount(t, keylogPath, 1, 2*time.Second)
	assert.Equal(t, line+"\n", got, "duplicate (label, client_random, secret) triples must collapse to one appended line")
}

// UT-02.5: a malformed line is rejected (never appended) and its content is
// never logged -- only a rejection count.
func TestSocketServer_MalformedLine_RejectedWithoutAppendOrContentLog(t *testing.T) {
	var logBuf bytes.Buffer
	s, sockPath, keylogPath := newTestSocketServer(t, WithLogger(logger.New(&logBuf)))

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)

	const sentinel = "NOTALABEL_SENTINEL_XYZ"
	malformed := sentinel + " " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48)
	_, err = conn.Write([]byte(malformed + "\n"))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.RejectedCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, int64(1), s.RejectedCount(), "malformed line must be counted as rejected")

	data, err := os.ReadFile(keylogPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Empty(t, string(data), "a malformed line must never be appended to the keylog")

	assert.NotContains(t, logBuf.String(), sentinel, "the rejected line's content must never appear in logs")
}

// UT-02.5 edge case: a connection that closes mid-line (no trailing newline)
// must not corrupt the keylog -- the partial data is rejected as malformed,
// never appended, and does not affect a prior well-formed line.
func TestSocketServer_ConnectionClosesMidLine_NoCorruption(t *testing.T) {
	_, sockPath, keylogPath := newTestSocketServer(t)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	goodLine := wellFormedLine()
	_, err = conn.Write([]byte(goodLine + "\n"))
	require.NoError(t, err)

	// Partial line, deliberately truncated (invalid hex length), no newline.
	partial := "CLIENT_RANDOM " + strings.Repeat("ab", 10)
	_, err = conn.Write([]byte(partial))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	got := waitForKeylogLineCount(t, keylogPath, 1, 2*time.Second)
	assert.Equal(t, goodLine+"\n", got, "only the prior well-formed line may be present; the truncated partial must never be appended")
}

// UT-02.6: the server refuses to listen when the socket directory is
// world-writable/readable (perm&0o066 != 0).
func TestSocketServer_RefusesWorldWritableSocketDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o777))

	_, err := NewSocketServer(SocketServerConfig{
		SocketPath: filepath.Join(dir, "keylog.sock"),
		KeylogPath: filepath.Join(dir, "sslkeylog.log"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWorldAccessibleSocketDir), "must refuse a world-writable socket directory")
}
