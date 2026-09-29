// Package logger provides the sidecar's structured JSON logger. It emits
// operator-facing telemetry only and redacts known secret-bearing fields so
// TLS key material and decrypted plaintext can never leak into logs.
package logger

import (
	"bytes"
	"context"
	"encoding"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
)

// sensitiveKeys never appear in cleartext. Security requirement: the sidecar
// handles plaintext-equivalent TLS secrets and must never log them. Entries
// are spelled as isSensitive normalizes a key: lower case, without '_', '-'
// or trailing digits. Names ending in "secret" or "secrets" need no entry.
var sensitiveKeys = map[string]struct{}{
	"clientrandom": {},
	"keylog":       {},
	"key":          {},
	"sessionkey":   {},
	"privatekey":   {},
	"psk":          {},
	"plaintext":    {},
}

// redactedValue replaces any sensitive field's value.
const redactedValue = "***REDACTED***"

// unloggableValue replaces a value the key match cannot see inside: a map,
// struct, slice, array or pointer. It differs from redactedValue so a reader
// can tell a field blocked for its type from one matched as a secret.
const unloggableValue = "***UNLOGGABLE***"

// Logger is a thin wrapper over slog that emits the sidecar's JSON log shape:
// {"level","timestamp","message","context":{...}}.
//
// Redaction matches attribute keys, at any group depth: a sensitive key, or
// a sensitive group enclosing it, masks the value. Since a key match cannot
// see inside a value, a value slog has no kind for (one passed via slog.Any)
// is logged only as a single string, number or bool; anything else is masked
// with unloggableValue. A type logged as several fields implements
// slog.LogValuer, which slog resolves into attrs the key match does see.
type Logger struct {
	inner *slog.Logger
}

// Option configures a Logger built by New.
type Option func(*options)

type options struct {
	level slog.Leveler
}

// WithLevel sets the minimum level logged; records below it are dropped.
// The default is slog.LevelInfo.
func WithLevel(level slog.Leveler) Option {
	return func(o *options) { o.level = level }
}

// New returns a Logger writing JSON records to w.
func New(w io.Writer, opts ...Option) *Logger {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: o.level, ReplaceAttr: replaceAttr})
	return &Logger{inner: slog.New(h)}
}

// replaceAttr renames slog's built-in time and message keys to the sidecar's
// "timestamp" and "message", and writes the time in UTC. Every other
// attribute -- a caller's attrs under "context", or any attr a future Logger
// method adds at the top level -- is masked when its key, or any enclosing
// group's key, is sensitive, and flattened or masked when opaque (see
// scalarAttr). slog calls it for each non-group attribute, including those
// nested in groups, after resolving LogValuers. The built-ins are matched
// only at the top level, so a caller attr named "time" or "msg" is never
// renamed.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			a.Key = "timestamp"
			if a.Value.Kind() == slog.KindTime {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		case slog.MessageKey:
			a.Key = "message"
			return a
		case slog.LevelKey, slog.SourceKey:
			return a
		}
	}
	if isSensitive(a.Key) || slices.ContainsFunc(groups, isSensitive) {
		return slog.String(a.Key, redactedValue)
	}
	if a.Value.Kind() == slog.KindAny {
		return scalarAttr(a)
	}
	return a
}

// scalarAttr rewrites an opaque attr as a single string, number or bool, or
// masks it with unloggableValue when it has no such form. The logger does
// the conversion itself, so encoding/json never sees a caller's value and a
// custom MarshalJSON cannot emit fields the key match never saw. A nil
// interface or nil pointer is logged as null, without calling its methods.
func scalarAttr(a slog.Attr) slog.Attr {
	v := a.Value.Any()
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.Kind() == reflect.Pointer && rv.IsNil() {
		return slog.Any(a.Key, nil)
	}
	switch v := v.(type) {
	case error, fmt.Stringer:
		return slog.String(a.Key, fmt.Sprint(v))
	case encoding.TextMarshaler:
		if text, err := v.MarshalText(); err == nil {
			return slog.String(a.Key, string(text))
		}
		return slog.String(a.Key, unloggableValue)
	}
	switch rv.Kind() {
	case reflect.Bool:
		return slog.Bool(a.Key, rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return slog.Int64(a.Key, rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return slog.Uint64(a.Key, rv.Uint())
	case reflect.Float32, reflect.Float64:
		return slog.Float64(a.Key, rv.Float())
	case reflect.String:
		return slog.String(a.Key, rv.String())
	}
	return slog.String(a.Key, unloggableValue)
}

// isSensitive reports whether key names secret material. It ignores case,
// '_', '-' and trailing digits, so client_random, clientRandom and
// CLIENT-RANDOM are one name, and it matches every name ending in "secret"
// or "secrets", such as the NSS label CLIENT_TRAFFIC_SECRET_0. A name that
// only contains a sensitive word, like keylog_lines_rejected, passes.
func isSensitive(key string) bool {
	var buf [64]byte
	name := buf[:0]
	for i := range len(key) {
		c := key[i]
		switch {
		case c == '_' || c == '-':
			continue
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		}
		name = append(name, c)
	}
	name = bytes.TrimRight(name, "0123456789")
	if _, ok := sensitiveKeys[string(name)]; ok {
		return true
	}
	return bytes.HasSuffix(name, []byte("secret")) || bytes.HasSuffix(name, []byte("secrets"))
}

// Info logs at INFO level with attrs grouped under "context".
func (l *Logger) Info(msg string, attrs ...slog.Attr) {
	l.log(slog.LevelInfo, msg, attrs)
}

// Warn logs at WARN level.
func (l *Logger) Warn(msg string, attrs ...slog.Attr) {
	l.log(slog.LevelWarn, msg, attrs)
}

// Error logs at ERROR level.
func (l *Logger) Error(msg string, attrs ...slog.Attr) {
	l.log(slog.LevelError, msg, attrs)
}

// log emits one record with attrs under "context", in the order given. slog
// omits an empty group, so a call without attrs has no "context" field.
func (l *Logger) log(level slog.Level, msg string, attrs []slog.Attr) {
	l.inner.LogAttrs(context.Background(), level, msg, slog.GroupAttrs("context", attrs...))
}
