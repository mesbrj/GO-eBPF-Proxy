// Command app is the sidecar entrypoint: it loads and attaches the eBPF
// connect4/sockops redirect, serves the pass-through relay, attaches the
// uprobe keylog consumer, and captures the outbound leg to a DSB-embedded
// pcapng file with bounded, ephemeral-by-default retention.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/keylog"
)

func main() {
	cfg := DefaultConfig()

	var opensslVer, tlsVer string
	flag.StringVar(&cfg.CgroupPath, "cgroup-path", "", "pod common-parent cgroup v2 path to attach connect4/sockops (required)")
	flag.IntVar(&cfg.TargetPID, "pid", 0, "target application PID to attach the TLS uprobe to (required)")
	flag.StringVar(&cfg.RelayListen, "relay-listen", cfg.RelayListen, "address the pass-through relay listens on")
	flag.StringVar(&cfg.PinDir, "pin-dir", cfg.PinDir, "bpffs directory for the connect4/sockops pinned maps")
	flag.StringVar(&cfg.LibsslPath, "libssl", "", "override path to the target's libssl (skips discovery)")
	flag.StringVar(&cfg.KeylogPinDir, "keylog-pin-dir", cfg.KeylogPinDir, "bpffs directory for the keylog uprobe's pinned maps")
	flag.StringVar(&cfg.KeylogPath, "keylog-path", cfg.KeylogPath, "path to the NSS keylog file (should be on tmpfs)")
	flag.StringVar(&opensslVer, "openssl-version", "3.x", "target libssl version bucket: 1.1.1, 3.0, or 3.x")
	flag.StringVar(&tlsVer, "tls-version", "1.3", "negotiated TLS version to extract: 1.2 or 1.3")
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
	if cfg.TargetPID == 0 {
		log.Fatal("app: --pid is required")
	}
	var err error
	cfg.OpenSSLVer, err = parseOpenSSLVersion(opensslVer)
	if err != nil {
		log.Fatalf("app: %v", err)
	}
	cfg.TLSVersion, err = parseTLSVersion(tlsVer)
	if err != nil {
		log.Fatalf("app: %v", err)
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

// parseOpenSSLVersion maps the --openssl-version flag to its offset-table bucket.
func parseOpenSSLVersion(s string) (keylog.OpenSSLVersion, error) {
	switch s {
	case "1.1.1":
		return keylog.OpenSSL111, nil
	case "3.0":
		return keylog.OpenSSL30, nil
	case "3.x":
		return keylog.OpenSSL3x, nil
	default:
		return keylog.OpenSSLUnknown, fmt.Errorf("--openssl-version: unknown value %q (want 1.1.1, 3.0, or 3.x)", s)
	}
}

// parseTLSVersion maps the --tls-version flag to its wire version constant.
func parseTLSVersion(s string) (uint16, error) {
	switch s {
	case "1.2":
		return keylog.TLSVersion12, nil
	case "1.3":
		return keylog.TLSVersion13, nil
	default:
		return 0, fmt.Errorf("--tls-version: unknown value %q (want 1.2 or 1.3)", s)
	}
}
