// Command app is the sidecar entrypoint: it loads and attaches the eBPF
// connect4/sockops redirect, serves the pass-through relay, runs the
// LD_PRELOAD-interposer keylog socket server, and captures the outbound leg
// to a DSB-embedded pcapng file with bounded, ephemeral-by-default retention.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
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
	flag.Parse()

	if cfg.CgroupPath == "" {
		log.Fatal("app: --cgroup-path is required")
	}

	a, err := Start(cfg)
	if err != nil {
		log.Fatalf("app: start: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	if err := a.Close(); err != nil {
		log.Fatalf("app: shutdown: %v", err)
	}
}
