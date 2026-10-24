package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/keylog"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/proxy"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// Config configures one run of the sidecar: eBPF redirect + relay, the
// LD_PRELOAD-interposer keylog socket server, and capture with bounded,
// ephemeral-by-default retention. Each koanf tag is the setting's key in
// every configuration source (see loadConfig).
type Config struct {
	CgroupPath       string        `koanf:"cgroup-path"`
	RelayListen      string        `koanf:"relay-listen"`
	PinDir           string        `koanf:"pin-dir"`
	KeylogSocketPath string        `koanf:"keylog-socket"`
	KeylogPath       string        `koanf:"keylog-path"`
	CaptureIface     string        `koanf:"capture-iface"`
	CapturePath      string        `koanf:"capture-path"`
	Retain           bool          `koanf:"retain"`
	MaxBytes         int64         `koanf:"max-bytes"`
	MaxAge           time.Duration `koanf:"max-age"`
	RetentionTick    time.Duration `koanf:"retention-interval"`
	StatsInterval    time.Duration `koanf:"stats-interval"`
	LogLevel         slog.Level    `koanf:"log-level"`
}

// DefaultConfig returns a Config populated with the sidecar's compiled-in
// defaults; the caller must still set CgroupPath and TargetPID.
func DefaultConfig() Config {
	return Config{
		RelayListen:      "127.0.0.1:15001",
		PinDir:           ebpf.DefaultConfig().PinDir,
		KeylogSocketPath: "/var/run/sidecar/keylog.sock",
		KeylogPath:       "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log",
		CaptureIface:     "eth0",
		CapturePath:      "/var/log/sidecar/dump.pcapng",
		MaxBytes:         100 * 1024 * 1024,
		MaxAge:           24 * time.Hour,
		RetentionTick:    5 * time.Minute,
		StatsInterval:    time.Minute,
		LogLevel:         slog.LevelInfo,
	}
}

// App is one running instance of every wired subsystem: the eBPF loader,
// the pass-through relay, the keylog socket server, and the live interface
// capture into its DSB-embedded pcapng writer.
type App struct {
	cfg       Config
	log       *logger.Logger
	loader    *ebpf.Loader
	ln        net.Listener
	resolver  *proxy.Resolver
	keylogSrv *keylog.SocketServer
	capW      *capture.Writer
	live      *capture.Live
	retention capture.Retention
	stopTick  chan struct{}
}

// Start refuses a keylog directory that is not on tmpfs and deletes any
// keylog an earlier run left, then loads and attaches the eBPF programs,
// starts the relay, creates this run's capture file when --max-bytes leaves
// room for one, starts the keylog socket server, and starts capture, with
// every subsystem logging through log. A run with no room for a capture
// starts everything else (AC 12). On any failure it tears down whatever was
// already started before returning the error (never leaks a partial run).
func Start(cfg Config, log *logger.Logger) (*App, error) {
	// First, before anything is loaded or created: a refused keylog leaves
	// nothing to tear down (AD-023). The keylog holds one run's keys, so a
	// file an earlier run left, killed before its Close, goes before the
	// keylog socket server opens its own.
	if err := checkKeylogTmpfs(cfg.KeylogPath); err != nil {
		return nil, err
	}
	if err := deleteKeylog(cfg.KeylogPath); err != nil {
		return nil, fmt.Errorf("app: delete leftover keylog at --keylog-path: %w", err)
	}
	a := &App{cfg: cfg, log: log}

	loader, err := ebpf.Load(ebpf.Config{
		CgroupPath: cfg.CgroupPath,
		PinDir:     cfg.PinDir,
		ProxyUID:   ebpf.ProxyUID,
		ProxyPort:  ebpf.ProxyPort,
	})
	if err != nil {
		return nil, fmt.Errorf("app: load ebpf: %w", err)
	}
	a.loader = loader
	if err := loader.Attach(cfg.CgroupPath); err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: attach ebpf: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.RelayListen)
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: listen %q: %w", cfg.RelayListen, err)
	}
	a.ln = ln
	a.resolver = newResolver(loader.OrigDstByTuple(), log)
	relay := newRelay(a.resolver, log)
	go func() { _ = relay.Serve(ln) }()

	// The capture writer exists before the keylog socket server, so the
	// server can stream every line it accepts into the capture (AD-018).
	if err := a.openCapture(); err != nil {
		_ = a.Close()
		return nil, err
	}
	if err := a.startKeylog(); err != nil {
		_ = a.Close()
		return nil, err
	}

	if a.capW != nil {
		live, err := capture.StartLive(cfg.CaptureIface, a.capW)
		if err != nil {
			_ = a.Close()
			return nil, fmt.Errorf("app: start capture: %w", err)
		}
		a.live = live
	}

	a.stopTick = make(chan struct{})
	if cfg.RetentionTick > 0 {
		go a.enforceRetentionPeriodically(a.stopTick)
	}
	if cfg.StatsInterval > 0 {
		go a.logStatsPeriodically(a.stopTick)
	}

	return a, nil
}

// openCapture applies --max-age and --max-bytes to the capture directory
// and, when there is room, creates this run's capture file (AD-020, AD-021).
// One age pass runs first, so captures past --max-age free their room before
// the size check (AC 13). When the finished captures leave no room for even a
// new file's header, it creates no file and logs why at ERROR: capture is
// then not started, and Start goes on without it (AC 11, AC 12).
func (a *App) openCapture() error {
	captureDir := filepath.Dir(a.cfg.CapturePath)
	if err := capture.CheckTarget(captureDir); err != nil {
		return err
	}
	a.retention = capture.Retention{Template: a.cfg.CapturePath, MaxBytes: a.cfg.MaxBytes, MaxAge: a.cfg.MaxAge, Retain: a.cfg.Retain}
	_ = a.retention.Enforce() // as on every retention tick, a capture that cannot be deleted keeps its share of the room
	room, err := a.retention.Room()
	if err != nil {
		return fmt.Errorf("app: size the capture's room: %w", err)
	}
	opts := capture.Options{Room: room, OnStop: a.logCaptureStop}
	if a.cfg.MaxBytes > 0 && room < capture.HeaderSize(opts) {
		a.log.Error("capture not started: --max-bytes already reached",
			slog.String("dir", captureDir),
			slog.Int64("owned_bytes", a.cfg.MaxBytes-room),
			slog.Int64("max_bytes", a.cfg.MaxBytes),
		)
		return nil
	}

	capW, err := capture.CreateRunCapture(a.cfg.CapturePath, opts)
	if err != nil {
		return fmt.Errorf("app: open capture writer: %w", err)
	}
	a.capW = capW
	// Set as soon as the file exists, so a failure later in Start still
	// deletes it, unless Retain is set.
	a.retention.Run = capW.Path()
	a.log.Info("capture started", slog.String("path", capW.Path()))
	return nil
}

// startKeylog starts the keylog socket server, streaming every line it
// appends into this run's capture. Its keylog follows the capture (AD-023):
// it appends lines only while capture is active, and once capture has
// stopped, or when it never started, it reads and discards them, so the app
// never blocks.
func (a *App) startKeylog() error {
	var sink func(line string)
	if a.capW != nil {
		sink = a.capW.AddSecret
	}
	srv, err := keylog.NewSocketServer(keylog.SocketServerConfig{
		SocketPath: a.cfg.KeylogSocketPath,
		KeylogPath: a.cfg.KeylogPath,
		Sink:       sink,
		Gate:       a.captureActive,
	}, keylog.WithLogger(a.log))
	if err != nil {
		return fmt.Errorf("app: start keylog socket server: %w", err)
	}
	a.keylogSrv = srv
	go func() { _ = srv.Run() }()
	return nil
}

// logCaptureStop logs the one WARN line of a capture stopped at --max-bytes
// (AC 4). owned_bytes is what the finished captures took of --max-bytes, plus
// this run's capture.
func (a *App) logCaptureStop(s capture.Stop) {
	a.log.Warn("capture stopped: --max-bytes reached",
		slog.String("path", s.Path),
		slog.Int64("capture_bytes", s.Bytes),
		slog.Int64("owned_bytes", a.cfg.MaxBytes-s.Room+s.Bytes),
		slog.Int64("max_bytes", a.cfg.MaxBytes),
	)
}

// captureState reports where this run's capture stands (door 4): not started
// when Start found --max-bytes already reached, otherwise its Writer's state.
func (a *App) captureState() capture.State {
	if a.capW == nil {
		return capture.StateNotStartedMaxBytes
	}
	return a.capW.State()
}

// captureActive reports whether this run's capture is active: the keylog's
// gate. It takes no lock, so it is cheap on every keylog line.
func (a *App) captureActive() bool {
	return a.captureState() == capture.StateActive
}

// enforceRetentionPeriodically bounds the capture directory's footprint
// while the sidecar runs, not just at teardown (spec: retention is never
// unbounded). It returns once stop is closed; stop is passed in rather than
// read from a.stopTick, which Close sets to nil concurrently.
func (a *App) enforceRetentionPeriodically(stop <-chan struct{}) {
	t := time.NewTicker(a.cfg.RetentionTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.enforceRetention()
		case <-stop:
			return
		}
	}
}

// enforceRetention runs one age pass, then hands an active capture the room
// that pass freed (AC 8). A stopped capture ignores it and stays stopped
// (AC 9).
func (a *App) enforceRetention() {
	_ = a.retention.Enforce()
	if a.capW == nil {
		return
	}
	if room, err := a.retention.Room(); err == nil {
		a.capW.SetRoom(room)
	}
}

// logStatsPeriodically emits the stats line every StatsInterval until stop is
// closed.
func (a *App) logStatsPeriodically(stop <-chan struct{}) {
	t := time.NewTicker(a.cfg.StatsInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.logStats()
		case <-stop:
			return
		}
	}
}

// logStats reports the sidecar's counters as one "stats" log line:
// origdst_lookup_miss (fail-closed resolver misses) and keylog_lines_rejected
// (malformed lines the keylog socket refused), both cumulative since start,
// so a log consumer derives rates from consecutive lines, plus capture_state,
// where capture stands (door 4).
func (a *App) logStats() {
	a.log.Info("stats",
		slog.Uint64("origdst_lookup_miss", a.resolver.Misses()),
		slog.Int64("keylog_lines_rejected", a.keylogSrv.RejectedCount()),
		slog.String("capture_state", a.captureState().String()),
	)
}

// Close stops every subsystem -- the capture is drained and closed, never
// rewritten: its secrets are already in the DSBs written live (AD-022) -- and,
// unless Config.Retain is set, deletes this run's capture
// (ephemeral-by-default teardown). Captures kept by earlier runs stay. Last,
// it deletes the keylog file, with or without Retain: every key in it is in
// the capture already, or belongs to a capture just deleted (AD-023). A
// subsystem that fails to close, or a keylog that cannot be deleted, never
// keeps the others open.
func (a *App) Close() error {
	var errs []error
	if a.stopTick != nil {
		close(a.stopTick)
		a.stopTick = nil
		// stopTick exists only once Start fully succeeded, so every counter's
		// source is up. Report the final values: a run shorter than
		// StatsInterval would otherwise never log them.
		if a.cfg.StatsInterval > 0 {
			a.logStats()
		}
	}
	if a.live != nil {
		// Stop waits for the packet-reading goroutine to exit, so it must
		// return before capW is touched: otherwise capW.Close below can race
		// with a concurrent capW.WritePacket call in that goroutine (data
		// race on capW's internal bufio.Writer).
		errs = append(errs, a.live.Stop())
	}
	if a.capW != nil {
		errs = append(errs, a.capW.Close())
	}
	if a.keylogSrv != nil {
		errs = append(errs, a.keylogSrv.Close())
	}
	if a.ln != nil {
		errs = append(errs, a.ln.Close())
	}
	if a.loader != nil {
		errs = append(errs, a.loader.Close())
	}
	errs = append(errs, a.retention.Cleanup())
	if err := deleteKeylog(a.cfg.KeylogPath); err != nil {
		errs = append(errs, fmt.Errorf("app: delete keylog at --keylog-path: %w", err))
	}
	return errors.Join(errs...)
}

// deleteKeylog deletes whatever entry is at the keylog path: the keylog file
// lives for one run (AD-023). A symlink is deleted itself, never its target.
// Nothing at the path, or no path at all, is not an error.
func deleteKeylog(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) { // #nosec G703 -- path is operator-supplied config (--keylog-path), not raw user input
		return err
	}
	return nil
}

// At most missLogBurst resolver misses are logged per missLogInterval:
// anything in the pod can connect to the relay port and trigger a miss at
// will. The stats line's origdst_lookup_miss still counts every one.
const (
	missLogBurst    = 10
	missLogInterval = time.Minute
)

// newResolver builds the fail-closed resolver over the origdst_by_tuple map m,
// logging each definitive miss with its source tuple, up to missLogBurst per
// missLogInterval: a bug signal (LRU undersizing) or an abuse signal (a
// direct, un-redirected connect to the relay port). Without it, the
// connection the relay resets leaves no trace.
func newResolver(m proxy.Lookuper, log *logger.Logger) *proxy.Resolver {
	missLog := log.Limited(missLogInterval, missLogBurst)
	return proxy.NewResolver(m, proxy.WithOnMiss(func(src netip.AddrPort) {
		missLog.Warn("connection reset: no original destination (fail-closed)", slog.String("src", src.String()))
	}))
}

// newRelay builds the relay over resolver, logging each resolved connection
// once with its original destination: at INFO once the upstream dial
// succeeds, or at WARN with the error when it fails -- the relay closes the
// client then, so the log is the only trace of the failure.
func newRelay(resolver *proxy.Resolver, log *logger.Logger) *proxy.Relay {
	return proxy.NewRelay(resolver,
		proxy.WithOnRelayed(func(dst netip.AddrPort) {
			log.Info("connection relayed", slog.String("orig_dst", dst.String()))
		}),
		proxy.WithOnDialErr(func(dst netip.AddrPort, err error) {
			log.Warn("upstream dial failed", slog.String("orig_dst", dst.String()), slog.String("error", err.Error()))
		}),
	)
}
