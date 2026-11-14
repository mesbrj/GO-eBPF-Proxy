// Package logger provides the sidecar's structured JSON logger. It emits
// operator-facing telemetry only and redacts known secret-bearing fields so
// TLS key material and decrypted plaintext can never leak into logs. It also
// masks, wherever they occur, the values it is told are secret (WithMasked).
package logger

import (
	"bytes"
	"cmp"
	"context"
	"encoding"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
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
//
// Masking matches text instead: see WithMasked.
type Logger struct {
	inner *slog.Logger
	limit *limiter // nil unless built by Limited
	mask  mask     // empty unless built WithMasked
}

// Option configures a Logger built by New.
type Option func(*options)

type options struct {
	level  slog.Leveler
	masked []string
}

// WithLevel sets the minimum level logged; records below it are dropped.
// The default is slog.LevelInfo.
func WithLevel(level slog.Leveler) Option {
	return func(o *options) { o.level = level }
}

// WithMasked makes the logger write redactedValue in place of every
// occurrence of each of values, in a record's message and in every field
// but its level and timestamp, whatever the field's key or type. It is for a
// secret whose text can come back from outside the sidecar under any key,
// such as a credential a server repeats in the error it answers with; the
// key match cannot catch that. Empty values are ignored. Where occurrences
// overlap or touch, the whole run is written as one redactedValue, so no
// part of a value is left beside it.
func WithMasked(values ...string) Option {
	return func(o *options) { o.masked = append(o.masked, values...) }
}

// New returns a Logger writing JSON records to w.
func New(w io.Writer, opts ...Option) *Logger {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	m := newMask(o.masked)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: o.level, ReplaceAttr: m.replaceAttr})
	return &Logger{inner: slog.New(h), mask: m}
}

// Mask returns s as the logger would write it, with every masked value
// replaced. A caller that shortens a text before logging it masks it first,
// so the cut cannot leave the head of a masked value behind.
func (l *Logger) Mask(s string) string {
	return l.mask.text(s)
}

// mask is the set of values a Logger never writes (see WithMasked).
type mask []string

// newMask returns the mask of values, without the empty ones: an empty value
// occurs everywhere.
func newMask(values []string) mask {
	return slices.DeleteFunc(slices.Clone(values), func(v string) bool { return v == "" })
}

// text returns s with each run of bytes that belong to an occurrence of a
// masked value replaced by one redactedValue.
func (m mask) text(s string) string {
	var spans [][2]int // [start, end) of every occurrence, overlapping ones included
	for _, v := range m {
		for from := 0; ; from++ {
			i := strings.Index(s[from:], v)
			if i < 0 {
				break
			}
			from += i
			spans = append(spans, [2]int{from, from + len(v)})
		}
	}
	if len(spans) == 0 {
		return s
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return cmp.Compare(a[0], b[0]) })
	var b strings.Builder
	written, run := 0, spans[0] // s[:written] is written; run is the run being grown
	for _, span := range spans[1:] {
		if span[0] <= run[1] {
			run[1] = max(run[1], span[1])
			continue
		}
		b.WriteString(s[written:run[0]])
		b.WriteString(redactedValue)
		written, run = run[1], span
	}
	b.WriteString(s[written:run[0]])
	b.WriteString(redactedValue)
	b.WriteString(s[run[1]:])
	return b.String()
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
//
// Last, the message and every other attribute that passed have the values
// of m masked in their text (see WithMasked). An attribute of another type
// whose text holds one, say a number equal to an all-digit secret, is
// written as the masked string.
func (m mask) replaceAttr(groups []string, a slog.Attr) slog.Attr {
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
			return m.attr(a)
		case slog.LevelKey, slog.SourceKey:
			return a
		}
	}
	if isSensitive(a.Key) || slices.ContainsFunc(groups, isSensitive) {
		return slog.String(a.Key, redactedValue)
	}
	if a.Value.Kind() == slog.KindAny {
		a = scalarAttr(a)
	}
	return m.attr(a)
}

// attr returns a with the values of m masked in its text. An attr that holds
// none is returned as it is, keeping its type.
func (m mask) attr(a slog.Attr) slog.Attr {
	if len(m) == 0 {
		return a
	}
	text := a.Value.String()
	if masked := m.text(text); masked != text {
		return slog.String(a.Key, masked)
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
// omits an empty group, so a call without attrs has no "context" field. A
// record below the level never reaches the limiter, so it is not counted as
// suppressed.
func (l *Logger) log(level slog.Level, msg string, attrs []slog.Attr) {
	ctx := context.Background()
	if !l.inner.Enabled(ctx, level) {
		return
	}
	if l.limit != nil {
		keep, dropped := l.limit.admit()
		if !keep {
			return
		}
		if dropped > 0 {
			// Clip so the append never writes into the caller's array.
			attrs = append(slices.Clip(attrs), slog.Int64("suppressed", dropped))
		}
	}
	l.inner.LogAttrs(ctx, level, msg, slog.GroupAttrs("context", attrs...))
}
