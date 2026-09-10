// Package logger provides the sidecar's structured JSON logger. It emits
// operator-facing telemetry only and redacts known secret-bearing fields so
// TLS key material and decrypted plaintext can never leak into logs.
package logger

import (
	"io"
	"log/slog"
	"strings"
)

// sensitiveKeys never appear in cleartext. Security requirement: the sidecar
// handles plaintext-equivalent TLS secrets and must never log them.
var sensitiveKeys = map[string]struct{}{
	"secret":        {},
	"secrets":       {},
	"client_random": {},
	"master_secret": {},
	"keylog":        {},
	"key":           {},
	"plaintext":     {},
}

// redactedValue replaces any sensitive field's value.
const redactedValue = "***REDACTED***"

// Logger is a thin wrapper over slog that emits the sidecar's JSON log shape:
// {"level","timestamp","message","context":{...}}.
type Logger struct {
	inner *slog.Logger
}

// New returns a Logger writing JSON records to w.
func New(w io.Writer) *Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				a.Key = "timestamp"
			case slog.MessageKey:
				a.Key = "message"
			}
			return a
		},
	})
	return &Logger{inner: slog.New(h)}
}

// redact returns the context as slog attributes, masking sensitive keys.
func redact(ctx map[string]any) []any {
	attrs := make([]any, 0, len(ctx))
	for k, v := range ctx {
		if _, bad := sensitiveKeys[strings.ToLower(k)]; bad {
			v = redactedValue
		}
		attrs = append(attrs, slog.Any(k, v))
	}
	return attrs
}

// Info logs at INFO level with the given context fields grouped under "context".
func (l *Logger) Info(msg string, ctx map[string]any) {
	l.inner.Info(msg, slog.Group("context", redact(ctx)...))
}

// Warn logs at WARN level.
func (l *Logger) Warn(msg string, ctx map[string]any) {
	l.inner.Warn(msg, slog.Group("context", redact(ctx)...))
}

// Error logs at ERROR level.
func (l *Logger) Error(msg string, ctx map[string]any) {
	l.inner.Error(msg, slog.Group("context", redact(ctx)...))
}
