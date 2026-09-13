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

	"github.com/gopacket/gopacket/pcapgo"

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
	}
}

// App is one running instance of every wired subsystem: the eBPF loader,
// the pass-through relay, the keylog socket server, and the DSB-embedded
// pcapng capture writer.
type App struct {
	cfg       Config
	loader    *ebpf.Loader
	ln        net.Listener
	keylogSrv *keylog.SocketServer
	capW      *capture.Writer
	ethHandle *pcapgo.EthernetHandle
	retention capture.Retention
	stopTick  chan struct{}
}

// Start loads and attaches the eBPF programs, starts the relay, starts the
// keylog socket server, and starts capture. On any failure it tears down
// whatever was already started before returning the error (never leaks a
// partial run).
func Start(cfg Config) (*App, error) {
	a := &App{cfg: cfg}

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
	log := logger.New(os.Stderr)
	relay := proxy.NewRelay(proxy.NewResolver(loader.OrigDstByTuple()), proxy.WithOnResolved(func(dst netip.AddrPort) {
		log.Info("connection relayed", map[string]any{"orig_dst": dst.String()})
	}))
	go func() { _ = relay.Serve(ln) }()

	keylogSrv, err := keylog.NewSocketServer(keylog.SocketServerConfig{
		SocketPath: cfg.KeylogSocketPath,
		KeylogPath: cfg.KeylogPath,
	})
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
	eth, err := pcapgo.NewEthernetHandle(cfg.CaptureIface)
	if err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("app: open capture interface %q: %w", cfg.CaptureIface, err)
	}
	a.ethHandle = eth
	go func() {
		for {
			data, ci, rerr := eth.ReadPacketData()
			if rerr != nil {
				return
			}
			_ = capW.WritePacket(ci, data)
		}
	}()

	a.stopTick = make(chan struct{})
	if cfg.RetentionTick > 0 {
		go a.enforceRetentionPeriodically()
	}

	return a, nil
}

// enforceRetentionPeriodically bounds the capture directory's footprint
// while the sidecar runs, not just at teardown (spec: retention is never
// unbounded).
func (a *App) enforceRetentionPeriodically() {
	t := time.NewTicker(a.cfg.RetentionTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = a.retention.Enforce()
		case <-a.stopTick:
			return
		}
	}
}

// Close embeds the final keylog into the capture as a DSB, stops every
// subsystem, and -- unless Config.Retain is set -- wipes the capture
// directory (ephemeral-by-default teardown).
func (a *App) Close() error {
	var errs []error
	if a.stopTick != nil {
		close(a.stopTick)
		a.stopTick = nil
	}
	if a.ethHandle != nil {
		errs = append(errs, a.ethHandle.Close())
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
