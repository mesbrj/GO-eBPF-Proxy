package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// syncBuffer is a bytes.Buffer safe for the relay's connection goroutines to
// log into while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// lookupFunc adapts a function to proxy.Lookuper, standing in for the
// origdst_by_tuple map.
type lookupFunc func(key, valueOut any) error

func (f lookupFunc) Lookup(key, valueOut any) error { return f(key, valueOut) }

// serveRelay runs newRelay over m on a loopback listener and returns the
// relay's address and the buffer it logs into.
func serveRelay(t *testing.T, m lookupFunc) (string, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = newRelay(m, logger.New(logs)).Serve(ln) }()
	return ln.Addr().String(), logs
}

// UT-01.6 / IT-01.10: a definitive resolver miss must reset the connection
// and log its source tuple -- the fail-closed RST otherwise leaves no trace.
func TestNewRelay_LogsResolverMissWithSourceTuple(t *testing.T) {
	addr, logs := serveRelay(t, func(_, _ any) error { return ciliumebpf.ErrKeyNotExist })

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = io.ReadAll(conn)
	require.Error(t, err, "a fail-closed miss must reset the connection, not close it gracefully")

	src := conn.LocalAddr().String()
	assert.Eventually(t, func() bool {
		out := logs.String()
		return strings.Contains(out, "no original destination") && strings.Contains(out, src)
	}, 2*time.Second, 10*time.Millisecond, "the miss must be logged with the client's source tuple %s", src)
}

// A resolved destination that refuses the upstream dial must be logged: the
// relay closes the client either way, so the log is the only signal.
func TestNewRelay_LogsUpstreamDialFailure(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dst := closed.Addr().(*net.TCPAddr).AddrPort()
	require.NoError(t, closed.Close())
	od, err := ebpf.OrigDst(dst.Addr(), dst.Port())
	require.NoError(t, err)

	addr, logs := serveRelay(t, func(_, valueOut any) error {
		*(valueOut.(*bpf.ProxyOrigDst)) = od
		return nil
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, _ = io.ReadAll(conn)

	assert.Eventually(t, func() bool {
		out := logs.String()
		return strings.Contains(out, "upstream dial failed") && strings.Contains(out, dst.String())
	}, 2*time.Second, 10*time.Millisecond, "the dial failure to %s must be logged", dst)
}
