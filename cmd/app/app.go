package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/ebpf"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/keylog"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/proxy"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// Config configures one run of the sidecar: eBPF redirect + relay, the
// LD_PRELOAD-interposer keylog socket server, and capture with bounded,
// ephemeral-by-default retention.
type Config struct {
	CgroupPath       string
	RelayListen      string
	PinDir           string
	KeylogSocketPath string
	KeylogPath       string
	CaptureIface     string
	CapturePath      string
	Retain           bool
	MaxBytes         int64
	MaxAge           time.Duration
	RetentionTick    time.Duration
	StatsInterval    time.Duration
}

// DefaultConfig returns a Config populated with the sidecar's compiled-in
// defaults; the caller must still set CgroupPath and TargetPID.
func DefaultConfig() Config {
	return Config{
		RelayListen:      "127.0.0.1:15001",
		PinDir:           ebpf.DefaultConfig().PinDir,
		KeylogSocketPath: "/var/run/sidecar/keylog.sock",
		KeylogPath:       "/var/log/sidecar/sslkeylog.log",
		CaptureIface:     "eth0",
		CapturePath:      "/var/log/sidecar/dump.pcapng",
		MaxBytes:         100 * 1024 * 1024,
		MaxAge:           24 * time.Hour,
		RetentionTick:    5 * time.Minute,
		StatsInterval:    time.Minute,
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

// Start loads and attaches the eBPF programs, starts the relay, starts the
// keylog socket server, and starts capture, with every subsystem logging
// through log. On any failure it tears down whatever was already started
// before returning the error (never leaks a partial run).
func Start(cfg Config, log *logger.Logger) (*App, error) {
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

	keylogSrv, err := keylog.NewSocketServer(keylog.SocketServerConfig{
		SocketPath: cfg.KeylogSocketPath,
		KeylogPath: cfg.KeylogPath,
	}, keylog.WithLogger(log))
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: start keylog socket server: %w", err)
	}
	a.keylogSrv = keylogSrv
	go func() { _ = keylogSrv.Run() }()

	captureDir := filepath.Dir(cfg.CapturePath)
	if err := capture.CheckTarget(captureDir); err != nil {
		_ = a.Close()
		return nil, err
	}
	// Set before any capture file is created so a failure below still wipes
	// whatever was partially written, unless Retain is set.
	a.retention = capture.Retention{Dir: captureDir, MaxBytes: cfg.MaxBytes, MaxAge: cfg.MaxAge, Retain: cfg.Retain}

	capW, err := capture.NewWriter(cfg.CapturePath, capture.Options{})
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: open capture writer: %w", err)
	}
	a.capW = capW
	live, err := capture.StartLive(cfg.CaptureIface, capW)
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: start capture: %w", err)
	}
	a.live = live

	a.stopTick = make(chan struct{})
	if cfg.RetentionTick > 0 {
		go a.enforceRetentionPeriodically(a.stopTick)
	}
	if cfg.StatsInterval > 0 {
		go a.logStatsPeriodically(a.stopTick)
	}

	return a, nil
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
			_ = a.retention.Enforce()
		case <-stop:
			return
		}
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
// (malformed lines the keylog socket refused). Both are cumulative since
// start, so a log consumer derives rates from consecutive lines.
func (a *App) logStats() {
	a.log.Info("stats", map[string]any{
		"origdst_lookup_miss":   a.resolver.Misses(),
		"keylog_lines_rejected": a.keylogSrv.RejectedCount(),
	})
}

// Close embeds the final keylog into the capture as a DSB, stops every
// subsystem, and -- unless Config.Retain is set -- wipes the capture
// directory (ephemeral-by-default teardown).
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
		// return before capW is touched: otherwise EmbedKeylog/capW.Close
		// below can race with a concurrent capW.WritePacket call in that
		// goroutine (data race on capW's internal bufio.Writer).
		errs = append(errs, a.live.Stop())
	}
	if a.capW != nil {
		if lines, err := readKeylogLines(a.cfg.KeylogPath); err == nil {
			errs = append(errs, a.capW.EmbedKeylog(lines))
		}
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
	if a.retention.Dir != "" {
		errs = append(errs, a.retention.Cleanup())
	}
	return errors.Join(errs...)
}

// newResolver builds the fail-closed resolver over the origdst_by_tuple map m,
// logging every definitive miss with its source tuple: a bug signal (LRU
// undersizing) or an abuse signal (a direct, un-redirected connect to the
// relay port). Without it, the connection the relay resets leaves no trace.
func newResolver(m proxy.Lookuper, log *logger.Logger) *proxy.Resolver {
	return proxy.NewResolver(m, proxy.WithOnMiss(func(src netip.AddrPort) {
		log.Warn("connection reset: no original destination (fail-closed)", map[string]any{"src": src.String()})
	}))
}

// newRelay builds the relay over resolver, logging every relayed connection's
// original destination and every upstream dial failure -- the relay closes
// the client either way, so the log is the only trace of the failure.
func newRelay(resolver *proxy.Resolver, log *logger.Logger) *proxy.Relay {
	return proxy.NewRelay(resolver,
		proxy.WithOnResolved(func(dst netip.AddrPort) {
			log.Info("connection relayed", map[string]any{"orig_dst": dst.String()})
		}),
		proxy.WithOnDialErr(func(err error) {
			log.Warn("upstream dial failed", map[string]any{"error": err.Error()})
		}),
	)
}

// readKeylogLines reads the keylog file's non-empty lines for embedding as a
// pcapng Decryption Secrets Block.
func readKeylogLines(path string) ([]string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path, not raw user input
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
