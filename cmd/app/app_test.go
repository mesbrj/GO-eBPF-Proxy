package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/keylog"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/proxy"
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

// missEverything is an origdst_by_tuple stand-in that holds no tuples, so
// every lookup is a definitive miss.
var missEverything = lookupFunc(func(_, _ any) error { return ciliumebpf.ErrKeyNotExist })

// serveRelay runs newRelay over m on a loopback listener and returns the
// relay's address and the buffer it logs into.
func serveRelay(t *testing.T, m lookupFunc) (string, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	log := logger.New(logs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = newRelay(newResolver(m, log), log).Serve(ln) }()
	return ln.Addr().String(), logs
}

// statsApp returns an App wired with just the two counter sources logStats
// reads -- a resolver over m and a running keylog socket server -- logging
// into the returned buffer, plus the keylog socket's path. The socket sits in
// a not-yet-created subdirectory so NewSocketServer creates it 0711 itself:
// t.TempDir() can be group-accessible under the process umask, which the
// server rightly refuses to listen under.
func statsApp(t *testing.T, m lookupFunc, statsInterval time.Duration) (*App, *syncBuffer, string) {
	t.Helper()
	logs := &syncBuffer{}
	log := logger.New(logs)
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock", "keylog.sock")
	srv, err := keylog.NewSocketServer(keylog.SocketServerConfig{
		SocketPath: sockPath,
		KeylogPath: filepath.Join(dir, "sslkeylog.log"),
	}, keylog.WithLogger(log))
	require.NoError(t, err)
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Close() })
	a := &App{cfg: Config{StatsInterval: statsInterval}, log: log, resolver: newResolver(m, log), keylogSrv: srv}
	return a, logs, sockPath
}

// UT-01.6 / IT-01.10: a definitive resolver miss must reset the connection
// and log its source tuple -- the fail-closed RST otherwise leaves no trace.
func TestNewRelay_LogsResolverMissWithSourceTuple(t *testing.T) {
	addr, logs := serveRelay(t, missEverything)

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

// The stats line must carry each counter's cumulative value under its own
// name. Two resolver misses and one rejected keylog line make the two values
// distinct, so a swapped or dropped field shows.
func TestApp_LogStatsReportsCumulativeCounters(t *testing.T) {
	a, logs, sockPath := statsApp(t, missEverything, 0)
	for range 2 {
		_, err := a.resolver.Resolve(netip.MustParseAddr("10.0.0.1"), 40000)
		require.ErrorIs(t, err, proxy.ErrNotFound)
	}
	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	_, err = io.WriteString(conn, "not an NSS keylog line\n")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return a.keylogSrv.RejectedCount() == 1 },
		2*time.Second, 10*time.Millisecond, "the keylog socket must reject the malformed line")

	a.logStats()

	out := logs.String()
	assert.Contains(t, out, `"message":"stats"`)
	assert.Contains(t, out, `"origdst_lookup_miss":2`)
	assert.Contains(t, out, `"keylog_lines_rejected":1`)
}

// The stats loop must log every StatsInterval and return once stop is closed.
func TestApp_LogStatsPeriodicallyUntilStopped(t *testing.T) {
	a, logs, _ := statsApp(t, missEverything, 10*time.Millisecond)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.logStatsPeriodically(stop)
	}()

	require.Eventually(t, func() bool { return strings.Count(logs.String(), `"message":"stats"`) >= 2 },
		2*time.Second, 10*time.Millisecond, "the stats line must repeat every StatsInterval")
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the stats loop must return once stop is closed")
	}
}

// Close must log the final counters, so a run shorter than StatsInterval still
// reports them.
func TestApp_CloseLogsFinalStats(t *testing.T) {
	a, logs, _ := statsApp(t, missEverything, time.Hour)
	a.stopTick = make(chan struct{})

	require.NoError(t, a.Close())
	assert.Contains(t, logs.String(), `"message":"stats"`)
}
