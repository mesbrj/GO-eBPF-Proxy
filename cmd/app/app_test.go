package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture"
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

	want := `"orig_dst":"` + dst.String() + `"`
	assert.Eventually(t, func() bool {
		out := logs.String()
		return strings.Contains(out, "upstream dial failed") && strings.Contains(out, want)
	}, 2*time.Second, 10*time.Millisecond, "the dial failure must be logged with %s", want)
	assert.NotContains(t, logs.String(), "connection relayed", "a connection whose dial failed was never relayed")
}

// Anything in the pod can connect to the relay port and trigger a miss, so
// only missLogBurst misses are logged per interval; the counter the stats
// line reports still sees every one.
func TestNewResolver_LimitsMissLogButCountsEveryMiss(t *testing.T) {
	logs := &syncBuffer{}
	r := newResolver(missEverything, logger.New(logs))
	for range missLogBurst + 5 {
		_, err := r.Resolve(netip.MustParseAddr("10.0.0.1"), 40000)
		require.ErrorIs(t, err, proxy.ErrNotFound)
	}

	assert.Equal(t, missLogBurst, strings.Count(logs.String(), "no original destination"))
	assert.Equal(t, uint64(missLogBurst+5), r.Misses())
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

// The fixed sizes the capture tests count in: an Ethernet capture's header
// (its SHB and IDB), and the Enhanced Packet Block of a 100 B packet.
const (
	headerBytes = 124
	epb100Bytes = 132
)

// captureDir returns a fresh, secret-grade (0700) capture directory.
// t.TempDir() itself can be group/other-readable, which capture.CheckTarget
// refuses.
func captureDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sidecar")
	require.NoError(t, os.Mkdir(dir, 0o700))
	return dir
}

// plantCapture writes a finished owned capture of size bytes called name into
// dir, with its mtime set to mtime, and returns its path. Its content is
// sparse: only its size and age matter here.
func plantCapture(t *testing.T, dir, name string, size int64, mtime time.Time) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	require.NoError(t, os.Truncate(path, size))
	require.NoError(t, os.Chtimes(path, mtime, mtime))
	return path
}

// captureConfig returns a Config whose capture template lies in dir.
func captureConfig(dir string, maxBytes int64, maxAge time.Duration) Config {
	return Config{CapturePath: filepath.Join(dir, "dump.pcapng"), MaxBytes: maxBytes, MaxAge: maxAge}
}

// captureApp returns an App wired only with cfg and a logger writing into the
// returned buffer: no eBPF, relay or keylog server, so it needs no privilege.
// openCapture, enforceRetention and Close run on it exactly as Start's App
// runs them. Close also runs at cleanup.
func captureApp(t *testing.T, cfg Config) (*App, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	a := &App{cfg: cfg, log: logger.New(logs)}
	t.Cleanup(func() { _ = a.Close() })
	return a, logs
}

// logRecord is one JSON line of the sidecar's log.
type logRecord struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Context map[string]any `json:"context"`
}

// logRecords returns every record in logs whose message is msg, in order.
func logRecords(t *testing.T, logs *syncBuffer, msg string) []logRecord {
	t.Helper()
	var records []logRecord
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec logRecord
		require.NoError(t, json.Unmarshal([]byte(line), &rec), "log line %q", line)
		if rec.Message == msg {
			records = append(records, rec)
		}
	}
	return records
}

// writePacket hands a's capture one packet of n bytes.
func writePacket(a *App, n int) error {
	return a.capW.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now()}, make([]byte, n))
}

// fillCapture writes 100 B packets into a's capture until one is refused,
// which must be with capture.ErrStopped, and returns how many were admitted.
func fillCapture(t *testing.T, a *App) int {
	t.Helper()
	for n := 0; n < 1<<16; n++ {
		if err := writePacket(a, 100); err != nil {
			require.ErrorIs(t, err, capture.ErrStopped)
			return n
		}
	}
	require.FailNow(t, "the capture never stopped")
	return 0
}

// fileSize returns the size of the file at path.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Size()
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

// readCapturePackets reads every packet of the closed capture at path through
// gopacket's own pcapng reader.
func readCapturePackets(t *testing.T, path string) [][]byte {
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

// C8 (AC 4): a capture stopped at --max-bytes logs one WARN line, however
// many packets are refused after it, giving this run's file and the sizes
// that stopped it.
func TestApp_CaptureStopLogsOneWarnWithSize(t *testing.T) {
	dir := captureDir(t)
	plantCapture(t, dir, "dump-1000000000.pcapng", 1000, time.Now())
	a, logs := captureApp(t, captureConfig(dir, 2000, 0))
	require.NoError(t, a.openCapture())
	require.NotNil(t, a.capW, "precondition: 1,000 B of a 2,000 B --max-bytes leaves room for a capture")

	admitted := fillCapture(t, a)
	for range 5 {
		assert.ErrorIs(t, writePacket(a, 100), capture.ErrStopped)
	}

	require.Equal(t, 6, admitted, "precondition: the 1,000 B room holds the header and six 132 B blocks")
	warns := logRecords(t, logs, "capture stopped: --max-bytes reached")
	require.Len(t, warns, 1, "exactly one WARN line; log: %s", logs)
	assert.Equal(t, "WARN", warns[0].Level)
	assert.Equal(t, a.capW.Path(), warns[0].Context["path"], "the WARN must name this run's file")
	assert.Equal(t, float64(headerBytes+6*epb100Bytes), warns[0].Context["capture_bytes"])
	assert.Equal(t, float64(1000+headerBytes+6*epb100Bytes), warns[0].Context["owned_bytes"], "owned_bytes is the finished capture plus this run's")
	assert.Equal(t, float64(2000), warns[0].Context["max_bytes"])
}

// C9 (AC 8): an age pass while capture is active hands the room it frees to
// the capture, which then admits what would not have fit before.
func TestApp_AgePassGrowsRoomOfActiveCapture(t *testing.T) {
	dir := captureDir(t)
	old := plantCapture(t, dir, "dump-1000000000.pcapng", 1000, time.Now())
	cfg := captureConfig(dir, 2000, time.Hour)
	cfg.Retain = true // keep this run's file to read it after Close
	a, _ := captureApp(t, cfg)
	require.NoError(t, a.openCapture())
	require.NotNil(t, a.capW, "precondition: the fresh capture survives the startup age pass, leaving room for this one")

	// Nine 68 B packets: 32 + 68 = 100 B of block each, 900 B in all, which
	// the 1,000 B room left beside the 124 B header (876 B) cannot hold.
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, twoHoursAgo, twoHoursAgo))
	a.enforceRetention()
	assert.NoFileExists(t, old, "the age pass must delete the capture past --max-age")

	for i := range 9 {
		require.NoError(t, writePacket(a, 68), "packet %d must fit the room the age pass freed", i)
	}
	assert.Equal(t, capture.StateActive, a.captureState())
	run := a.capW.Path()
	require.NoError(t, a.Close())
	assert.Len(t, readCapturePackets(t, run), 9)
}

// C10 (AC 9): once capture has stopped, an age pass that frees room neither
// restarts it nor starts a second capture file.
func TestApp_StoppedCaptureStaysStoppedAfterAgePass(t *testing.T) {
	dir := captureDir(t)
	old := plantCapture(t, dir, "dump-1000000000.pcapng", 1000, time.Now())
	cfg := captureConfig(dir, 2000, time.Hour)
	cfg.Retain = true
	a, _ := captureApp(t, cfg)
	require.NoError(t, a.openCapture())
	admitted := fillCapture(t, a)
	run := a.capW.Path()
	size := int64(headerBytes + admitted*epb100Bytes)
	require.Eventually(t, func() bool { return fileSize(t, run) == size }, 2*time.Second, 20*time.Millisecond,
		"precondition: everything admitted before the stop is written")

	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(old, twoHoursAgo, twoHoursAgo))
	a.enforceRetention()
	require.NoFileExists(t, old, "precondition: the age pass deletes the finished capture")

	assert.Equal(t, capture.StateStoppedMaxBytes, a.captureState())
	assert.ErrorIs(t, writePacket(a, 100), capture.ErrStopped)
	time.Sleep(1500 * time.Millisecond) // a packet admitted now would be on disk by then
	assert.Equal(t, size, fileSize(t, run), "a packet after the pass must not reach this run's file")
	assert.Equal(t, []string{filepath.Base(run)}, dirNames(t, dir), "no new capture file may appear")
}

// C11 (AC 10): --max-bytes 0 sets no limit, whatever the directory holds.
func TestApp_ZeroMaxBytesAppliesNoLimit(t *testing.T) {
	dir := captureDir(t)
	plantCapture(t, dir, "dump-1000000000.pcapng", 1<<20, time.Now())
	cfg := captureConfig(dir, 0, 0)
	cfg.Retain = true
	a, _ := captureApp(t, cfg)
	require.NoError(t, a.openCapture())
	require.NotNil(t, a.capW, "--max-bytes 0 must start capture")

	const packets = 32 // 32 x 64 KiB = 2 MiB
	for i := range packets {
		require.NoError(t, writePacket(a, 64<<10), "packet %d", i)
	}
	assert.Equal(t, capture.StateActive, a.captureState())
	run := a.capW.Path()
	require.NoError(t, a.Close())
	assert.Len(t, readCapturePackets(t, run), packets)
}

// C12 (AC 6, AC 7): a stop at --max-bytes never makes shutdown fail, and with
// --retain the stopped capture is kept exactly as it was.
func TestApp_CloseAfterCaptureStopSucceeds(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(fmt.Sprintf("retain=%t", retain), func(t *testing.T) {
			dir := captureDir(t)
			cfg := captureConfig(dir, 1000, 0)
			cfg.Retain = retain
			a, _ := captureApp(t, cfg)
			require.NoError(t, a.openCapture())
			admitted := fillCapture(t, a)
			run := a.capW.Path()
			size := int64(headerBytes + admitted*epb100Bytes)
			require.Eventually(t, func() bool { return fileSize(t, run) == size }, 2*time.Second, 20*time.Millisecond,
				"precondition: everything admitted before the stop is written")

			require.NoError(t, a.Close(), "Close after a stop at --max-bytes must succeed")
			if retain {
				assert.Equal(t, size, fileSize(t, run), "--retain must keep the stopped capture at the size it had")
			} else {
				assert.NoFileExists(t, run)
			}
		})
	}
}

// C17 (AC 11): capture starts only when the finished captures leave room for
// a new file's header. Otherwise no file is created, the state says why, and
// one ERROR line gives the numbers.
func TestApp_StartCaptureNeedsRoomForTheHeader(t *testing.T) {
	const maxBytes = 10_000
	for _, tc := range []struct {
		name   string
		owned  int64
		starts bool
	}{
		{"owned M-124", maxBytes - headerBytes, true},
		{"owned M-123", maxBytes - headerBytes + 1, false},
		{"owned M", maxBytes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := captureDir(t)
			plantCapture(t, dir, "dump-1000000000.pcapng", tc.owned, time.Now())
			a, logs := captureApp(t, captureConfig(dir, maxBytes, 0))
			require.NoError(t, a.openCapture())
			notStarted := logRecords(t, logs, "capture not started: --max-bytes already reached")

			if tc.starts {
				require.NotNil(t, a.capW, "capture must start")
				assert.Equal(t, capture.StateActive, a.captureState())
				assert.Equal(t, int64(headerBytes), fileSize(t, a.capW.Path()))
				assert.Equal(t, int64(maxBytes), tc.owned+fileSize(t, a.capW.Path()), "the owned captures then total --max-bytes exactly")
				assert.Empty(t, notStarted)
				return
			}
			assert.Nil(t, a.capW, "capture must not start")
			assert.Equal(t, capture.StateNotStartedMaxBytes, a.captureState())
			assert.Equal(t, []string{"dump-1000000000.pcapng"}, dirNames(t, dir), "no capture file may be created")
			require.Len(t, notStarted, 1, "exactly one ERROR line; log: %s", logs)
			assert.Equal(t, "ERROR", notStarted[0].Level)
			assert.Equal(t, dir, notStarted[0].Context["dir"])
			assert.Equal(t, float64(tc.owned), notStarted[0].Context["owned_bytes"])
			assert.Equal(t, float64(maxBytes), notStarted[0].Context["max_bytes"])
		})
	}
}

// C20 (AC 13): the startup age pass runs before the size check, so a capture
// past --max-age gives its room to the new one.
func TestApp_StartupAgePassRunsBeforeSizeCheck(t *testing.T) {
	const maxBytes = 10_000
	for _, tc := range []struct {
		maxAge time.Duration
		starts bool
	}{
		{time.Hour, true},
		{0, false},
	} {
		t.Run("max-age "+tc.maxAge.String(), func(t *testing.T) {
			dir := captureDir(t)
			old := plantCapture(t, dir, "dump-1000000000.pcapng", maxBytes, time.Now().Add(-2*time.Hour))
			a, _ := captureApp(t, captureConfig(dir, maxBytes, tc.maxAge))
			require.NoError(t, a.openCapture())

			if tc.starts {
				assert.NoFileExists(t, old, "the startup age pass must delete the expired capture")
				assert.NotNil(t, a.capW, "capture must start in the room it freed")
				return
			}
			assert.FileExists(t, old, "--max-age 0 deletes nothing")
			assert.Nil(t, a.capW, "with the capture kept there is no room")
			assert.Equal(t, capture.StateNotStartedMaxBytes, a.captureState())
		})
	}
}

// C55 (AC 37, door 4): every stats line, the final one Close logs included,
// says where capture stands.
func TestApp_LogStatsReportsCaptureState(t *testing.T) {
	const maxBytes = 10_000
	for _, tc := range []struct {
		state string
		owned int64 // a finished capture already in the directory
		fill  bool  // write until capture stops
	}{
		{"active", 0, false},
		{"stopped_max_bytes", 0, true},
		{"not_started_max_bytes", maxBytes, false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			a, logs, _ := statsApp(t, missEverything, time.Hour)
			dir := captureDir(t)
			if tc.owned > 0 {
				plantCapture(t, dir, "dump-1000000000.pcapng", tc.owned, time.Now())
			}
			a.cfg.CapturePath = filepath.Join(dir, "dump.pcapng")
			a.cfg.MaxBytes = maxBytes
			require.NoError(t, a.openCapture())
			if tc.fill {
				fillCapture(t, a)
			}

			a.logStats()
			stats := logRecords(t, logs, "stats")
			require.Len(t, stats, 1)
			assert.Equal(t, tc.state, stats[0].Context["capture_state"])

			a.stopTick = make(chan struct{})
			require.NoError(t, a.Close())
			stats = logRecords(t, logs, "stats")
			require.Len(t, stats, 2, "Close must log the final stats line")
			assert.Equal(t, tc.state, stats[1].Context["capture_state"], "the final stats line must carry the state too")
		})
	}
}

// C56 (AC 38): starting capture logs one INFO line naming this run's file.
func TestApp_CaptureStartLogsInfoWithPath(t *testing.T) {
	dir := captureDir(t)
	a, logs := captureApp(t, captureConfig(dir, 10_000, 0))
	require.NoError(t, a.openCapture())
	require.NotNil(t, a.capW)

	started := logRecords(t, logs, "capture started")
	require.Len(t, started, 1, "exactly one INFO line; log: %s", logs)
	assert.Equal(t, "INFO", started[0].Level)
	assert.Equal(t, a.capW.Path(), started[0].Context["path"])
	assert.FileExists(t, a.capW.Path())
	assert.Equal(t, dir, filepath.Dir(a.capW.Path()))
	assert.Regexp(t, `^dump-[0-9]+\.pcapng$`, filepath.Base(a.capW.Path()))
}
