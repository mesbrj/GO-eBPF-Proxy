// Command app is the sidecar entrypoint: it loads and attaches the eBPF
// connect4/sockops redirect, serves the pass-through relay, runs the
// LD_PRELOAD-interposer keylog socket server, and captures the outbound leg
// to a DSB-embedded pcapng file with bounded, ephemeral-by-default retention.
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

func main() {
	// The level is known only once the configuration loads; until then the
	// zero LevelVar keeps INFO, so a config error is still logged.
	var level slog.LevelVar
	log := logger.New(os.Stderr, logger.WithLevel(&level))

	cfg, err := loadConfig(flag.CommandLine, os.Args[1:], os.Environ())
	if err != nil {
		fatal(log, "app: config load failed", err)
	}
	level.Set(cfg.LogLevel)
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
	var attrs []slog.Attr
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	log.Error(msg, attrs...)
	os.Exit(1)
}
