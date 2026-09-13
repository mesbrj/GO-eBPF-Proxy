// Package keylog implements the sidecar-side transport for the LD_PRELOAD
// interposer's TLS session-key lines: a Unix-socket server that accepts
// interposer connections, reads newline-delimited NSS lines, and routes each
// through the existing validate/dedup/append pipeline (Writer.Append).
package keylog

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// SocketServerConfig configures a SocketServer.
type SocketServerConfig struct {
	// SocketPath is the Unix domain socket the interposer connects to.
	SocketPath string
	// KeylogPath is the NSS keylog file appended to via Writer.
	KeylogPath string
}

// ErrWorldAccessibleSocketDir is returned when the socket's parent directory
// is group/other writable or readable: refuse to listen rather than expose a
// plaintext-equivalent secret transport outside the pod-exclusive volume.
// See design.md's Tech Decisions: perm&0o066 (not the stricter 0o077 used by
// capture.CheckTarget) so a different app UID can still traverse the dir.
var ErrWorldAccessibleSocketDir = errors.New("keylog: refusing to listen under a world-writable/readable socket directory")

// SocketServerOption configures optional SocketServer behavior.
type SocketServerOption func(*SocketServer)

// WithLogger overrides the default stderr logger (mirrors proxy.RelayOption).
func WithLogger(l *logger.Logger) SocketServerOption {
	return func(s *SocketServer) { s.log = l }
}

// SocketServer accepts interposer connections on a Unix domain socket and
// routes each newline-delimited line through Writer.Append.
type SocketServer struct {
	ln         net.Listener
	writer     *Writer
	socketPath string
	log        *logger.Logger
	rejected   int64
}

// NewSocketServer creates the socket directory (0711) if missing, refuses to
// listen if that directory is group/other writable or readable, removes a
// stale socket file, listens, chmods the socket file 0666 (so a different
// app UID can connect), and opens the keylog Writer.
func NewSocketServer(cfg SocketServerConfig, opts ...SocketServerOption) (*SocketServer, error) {
	dir := filepath.Dir(cfg.SocketPath)
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return nil, fmt.Errorf("keylog: create socket dir %q: %w", dir, err)
	}
	if err := checkSocketDir(dir); err != nil {
		return nil, err
	}

	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("keylog: remove stale socket %q: %w", cfg.SocketPath, err)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("keylog: listen %q: %w", cfg.SocketPath, err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o666); err != nil { // #nosec G302 -- cross-UID IPC rendezvous point; dir is the trust boundary
		_ = ln.Close()
		return nil, fmt.Errorf("keylog: chmod socket %q: %w", cfg.SocketPath, err)
	}

	w, err := NewWriter(cfg.KeylogPath)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("keylog: open keylog writer: %w", err)
	}

	s := &SocketServer{ln: ln, writer: w, socketPath: cfg.SocketPath, log: logger.New(os.Stderr)}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// checkSocketDir refuses a socket directory that is group/other writable or
// readable (perm&0o066 != 0). A missing directory is not an error here (it is
// created by the caller before this check runs).
func checkSocketDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("keylog: stat %q: %w", dir, err)
	}
	if perm := info.Mode().Perm(); perm&0o066 != 0 {
		return fmt.Errorf("%w: %q has mode %o", ErrWorldAccessibleSocketDir, dir, perm)
	}
	return nil
}

// Run accepts connections until the listener is closed, serving each on its
// own goroutine. It returns the (non-nil) error that stopped the accept loop,
// which is expected to be the listener-closed error during normal shutdown.
func (s *SocketServer) Run() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

// handleConn reads newline-delimited lines from conn until it closes, routing
// each through Writer.Append. A malformed line increments the rejection
// counter and is logged without its content; a partial trailing line left
// when the connection closes mid-write is rejected by Append's validation
// the same way, so it can never corrupt the keylog.
func (s *SocketServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if err := s.writer.Append(line); err != nil {
			// Log before the atomic increment: RejectedCount()'s observed
			// value must happen-after this log write (via the atomic
			// add/load pair below), never used as a proxy signal that
			// races ahead of it.
			s.log.Warn("keylog: socket server rejected a malformed line", nil)
			atomic.AddInt64(&s.rejected, 1)
		}
	}
}

// RejectedCount reports how many malformed lines have been rejected so far.
func (s *SocketServer) RejectedCount() int64 {
	return atomic.LoadInt64(&s.rejected)
}

// Close closes the listener and the keylog writer, and removes the socket
// file.
func (s *SocketServer) Close() error {
	var errs []error
	if s.ln != nil {
		errs = append(errs, s.ln.Close())
	}
	if s.writer != nil {
		errs = append(errs, s.writer.Close())
	}
	if s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
