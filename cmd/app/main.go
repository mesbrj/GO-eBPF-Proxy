// Command app is the sidecar entrypoint: it loads and attaches the eBPF
// connect4/sockops redirect, serves the pass-through relay, runs the
// LD_PRELOAD-interposer keylog socket server, and captures every frame on the
// capture interface (the relay's outbound leg and all other pod traffic) to a
// DSB-embedded pcapng file with bounded, ephemeral-by-default retention.
package main

import (
	"flag"
	"io"
	stdlog "log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mesbrj/netloupe-tap/internal/shared/logger"
)

func main() {
	// The level is known only once the configuration loads; until then the
	// zero LevelVar keeps INFO, so a config error is still logged.
	var level slog.LevelVar
	log := newLogger(os.Stderr, &level, os.Environ())
	captureStdLog(log)

	cfg, err := loadConfig(flag.CommandLine, os.Args[1:], os.Environ())
	if err != nil {
		fatal(log, "app: config load failed", err)
	}
	level.Set(cfg.LogLevel)
	if cfg.CgroupPath == "" {
		fatal(log, "app: --cgroup-path is required", nil)
	}

	// Before Start, so a signal that arrives while it runs is held in the
	// channel and still ends in a clean Close instead of killing the process.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	a, err := Start(cfg, log)
	if err != nil {
		fatal(log, "app: start failed", err)
	}
	<-sig

	if err := a.Close(); err != nil {
		fatal(log, "app: shutdown failed", err)
	}
}

// newLogger builds the sidecar's logger: JSON records to w at level, with
// the collector's request headers, as environ gives them to the metrics
// exporter, masked wherever their text occurs (AD-033). The values are in
// the environment before any setting is loaded, so even the first line
// logged is covered.
func newLogger(w io.Writer, level slog.Leveler, environ []string) *logger.Logger {
	return logger.New(w, logger.WithLevel(level), logger.WithMasked(otlpHeaderSecrets(environ)...))
}

// captureStdLog sends what Go's standard logger is given through log, as
// WARN records, instead of straight to stderr. Go's own libraries write
// there: net/http does when a server sends bytes nobody asked for, and it
// quotes them, so a peer chooses the text. It is masked and cut like the
// error of a failed push, and rate-limited like any event a peer can
// trigger at will.
func captureStdLog(log *logger.Logger) {
	stdlog.SetFlags(0)
	stdlog.SetOutput(stdLogWriter{log.Limited(exportLogInterval, exportLogBurst)})
}

// stdLogWriter writes each message of Go's standard logger as one record.
type stdLogWriter struct{ log *logger.Logger }

func (w stdLogWriter) Write(p []byte) (int, error) {
	text := strings.TrimRight(string(p), "\n")
	w.log.Warn("go library log", slog.String("text", peerText(w.log, text)))
	return len(p), nil
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
