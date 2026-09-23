// Command app is the sidecar entrypoint: it loads and attaches the eBPF
// connect4/sockops redirect, serves the pass-through relay, runs the
// LD_PRELOAD-interposer keylog socket server, and captures the outbound leg
// to a DSB-embedded pcapng file with bounded, ephemeral-by-default retention.
package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

func main() {
	cfg := DefaultConfig()

	flag.StringVar(&cfg.CgroupPath, "cgroup-path", "", "pod common-parent cgroup v2 path to attach connect4/sockops (required)")
	flag.StringVar(&cfg.RelayListen, "relay-listen", cfg.RelayListen, "address the pass-through relay listens on")
	flag.StringVar(&cfg.PinDir, "pin-dir", cfg.PinDir, "bpffs directory for the connect4/sockops pinned maps")
	flag.StringVar(&cfg.KeylogSocketPath, "keylog-socket", cfg.KeylogSocketPath, "unix domain socket the LD_PRELOAD keylog interposer connects to")
	flag.StringVar(&cfg.KeylogPath, "keylog-path", cfg.KeylogPath, "path to the NSS keylog file (should be on tmpfs)")
	flag.StringVar(&cfg.CaptureIface, "capture-iface", cfg.CaptureIface, "interface to capture the outbound leg from")
	flag.StringVar(&cfg.CapturePath, "capture-path", cfg.CapturePath, "path to the DSB-embedded pcapng capture file")
	flag.BoolVar(&cfg.Retain, "retain", cfg.Retain, "keep capture/keylog artifacts on teardown instead of wiping them")
	flag.Int64Var(&cfg.MaxBytes, "max-bytes", cfg.MaxBytes, "capture directory size cap in bytes (0 disables)")
	flag.DurationVar(&cfg.MaxAge, "max-age", cfg.MaxAge, "capture artifact age cap (0 disables)")
	flag.DurationVar(&cfg.RetentionTick, "retention-interval", cfg.RetentionTick, "how often to enforce retention while running (0 disables)")
	flag.DurationVar(&cfg.StatsInterval, "stats-interval", cfg.StatsInterval, "how often to log the cumulative counters as a \"stats\" line, plus once at shutdown (0 disables)")
	flag.Parse()

	log := logger.New(os.Stderr)
	if cfg.CgroupPath == "" {
		fatal(log, "app: --cgroup-path is required", nil)
	}

	a, err := Start(cfg, log)
	if err != nil {
		fatal(log, "app: start failed", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	if err := a.Close(); err != nil {
		fatal(log, "app: shutdown failed", err)
	}
}

// fatal logs msg (and err, if any) at ERROR and exits 1. It goes through the
// sidecar's JSON logger rather than the standard library's plain-text log so
// that a log pipeline parsing the sidecar's output also sees why it exited.
func fatal(log *logger.Logger, msg string, err error) {
	var ctx map[string]any
	if err != nil {
		ctx = map[string]any{"error": err.Error()}
	}
	log.Error(msg, ctx)
	os.Exit(1)
}
