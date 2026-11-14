package logger

import (
	"bytes"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The values the masking tests tell the logger are secret.
const (
	maskedToken = "tok-0123456789abcdef"
	maskedPIN   = "4815162342"
)

// A masked value is written as redactedValue wherever it occurs: in the
// message, in a string field under any key, in a field nested in a group,
// in an error, and in a number whose digits are the value. Nothing else in
// the record changes.
func TestWithMasked_MasksEveryOccurrence(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, WithMasked(maskedToken, maskedPIN)).Warn("push failed for "+maskedToken,
		slog.String("error", "401 (body: bad credentials "+maskedToken+", again "+maskedToken+")"),
		slog.Group("response", slog.String("location", "/moved?auth="+maskedToken)),
		slog.Any("cause", errors.New("server said "+maskedToken)),
		slog.Int64("bytes", 4815162342),
		slog.Int64("other_bytes", 42),
		slog.String("orig_dst", "93.184.216.34:443"),
	)

	assert.NotContains(t, buf.String(), maskedToken)
	assert.NotContains(t, buf.String(), maskedPIN)
	rec := decode(t, &buf)
	assert.Equal(t, "push failed for "+redactedValue, rec["message"])
	assert.Equal(t, "WARN", rec["level"])
	assert.NotEmpty(t, rec["timestamp"])
	ctx := rec["context"].(map[string]any)
	assert.Equal(t, "401 (body: bad credentials "+redactedValue+", again "+redactedValue+")", ctx["error"])
	assert.Equal(t, map[string]any{"location": "/moved?auth=" + redactedValue}, ctx["response"])
	assert.Equal(t, "server said "+redactedValue, ctx["cause"])
	assert.Equal(t, redactedValue, ctx["bytes"], "a number that is the value is written masked")
	assert.InDelta(t, 42, ctx["other_bytes"], 0, "a number that holds no value stays a number")
	assert.Equal(t, "93.184.216.34:443", ctx["orig_dst"])
}

// Where occurrences overlap, touch or lie one inside another, the whole run
// is masked: masking one occurrence must never leave part of another beside
// it, in whichever order the values were given.
func TestWithMasked_OverlappingOccurrencesLeaveNoPart(t *testing.T) {
	for name, tc := range map[string]struct {
		values     []string
		text, want string
	}{
		"the second value starts inside the first": {
			[]string{"AAAABBBBCCCC", "BBBBCCCCDDDD"}, "<AAAABBBBCCCCDDDD>", "<" + redactedValue + ">",
		},
		"the same, with the values given in the other order": {
			[]string{"BBBBCCCCDDDD", "AAAABBBBCCCC"}, "<AAAABBBBCCCCDDDD>", "<" + redactedValue + ">",
		},
		"touching": {
			[]string{"AAAABBBBCCCC", "BBBBCCCCDDDD"}, "<AAAABBBBCCCCBBBBCCCCDDDD>", "<" + redactedValue + ">",
		},
		"a value that overlaps its own next occurrence": {
			[]string{"XYXYXYXY"}, "<XYXYXYXYXY>", "<" + redactedValue + ">",
		},
		"one value inside another, at its start": {
			[]string{"tenant-0123456789abcdef-secretpart", "tenant-0123456789abcdef"}, "<tenant-0123456789abcdef-secretpart>", "<" + redactedValue + ">",
		},
		"one value inside another, in its middle": {
			[]string{"OUTER-inner-value-TAIL", "inner-value"}, "<OUTER-inner-value-TAIL>", "<" + redactedValue + ">",
		},
		"one value inside another, at its end": {
			[]string{"Bearer tok-0123456789", "tok-0123456789"}, "<Bearer tok-0123456789>", "<" + redactedValue + ">",
		},
		"the inner value given first": {
			[]string{"inner-value", "OUTER-inner-value-TAIL"}, "<OUTER-inner-value-TAIL>", "<" + redactedValue + ">",
		},
		"apart": {
			[]string{"AAAABBBBCCCC", "BBBBCCCCDDDD"}, "AAAABBBBCCCC-BBBBCCCCDDDD", redactedValue + "-" + redactedValue,
		},
		"a part of a value alone is not a value": {
			[]string{"AAAABBBBCCCC", "BBBBCCCCDDDD"}, "<AAAABBBB>", "<AAAABBBB>",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, WithMasked(tc.values...)).Info("m", slog.String("v", tc.text))

			assert.Equal(t, tc.want, decode(t, &buf)["context"].(map[string]any)["v"])
		})
	}
}

// A field of any type is masked in the text the handler writes for it: a
// duration is written as nanoseconds, a float as JSON formats it, a time in
// RFC 3339. A field that holds no value keeps its type.
func TestWithMasked_MasksEveryFieldKindAsWritten(t *testing.T) {
	at := time.Date(2026, 11, 14, 2, 7, 25, 123456789, time.UTC)
	var buf bytes.Buffer
	New(&buf, WithMasked("12345678", "07:25.123456789", "true-ish")).Info("m",
		slog.Int64("int", 12345678),
		slog.Uint64("uint", 9912345678),
		slog.Float64("float", 123456789),
		slog.Duration("duration", 12345678*time.Nanosecond),
		slog.Time("time", at),
		slog.Bool("bool", true),
		slog.Float64("other_float", 1.5),
		slog.Duration("other_duration", 5*time.Second),
		slog.Time("other_time", at.Add(time.Hour).Truncate(time.Second)),
	)

	assert.NotContains(t, buf.String(), "12345678")
	assert.NotContains(t, buf.String(), "07:25.123456789")
	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, redactedValue, ctx["int"])
	assert.Equal(t, "99"+redactedValue, ctx["uint"])
	assert.Equal(t, redactedValue+"9", ctx["float"])
	assert.Equal(t, redactedValue, ctx["duration"])
	assert.Equal(t, "2026-11-14T02:"+redactedValue+"Z", ctx["time"])
	assert.Equal(t, true, ctx["bool"])
	assert.InDelta(t, 1.5, ctx["other_float"], 0)
	assert.InDelta(t, 5e9, ctx["other_duration"], 0)
	assert.Equal(t, "2026-11-14T03:07:25Z", ctx["other_time"])
}

// An empty value occurs everywhere, so it is ignored instead of masking the
// whole record; the other values still are.
func TestWithMasked_IgnoresEmptyValues(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, WithMasked("", maskedToken, "")).Info("relayed", slog.String("v", "x "+maskedToken+" y"))

	rec := decode(t, &buf)
	assert.Equal(t, "relayed", rec["message"])
	assert.Equal(t, "x "+redactedValue+" y", rec["context"].(map[string]any)["v"])
}

// Without masked values, and for a record that holds none, the logger writes
// what it always wrote.
func TestWithMasked_LeavesOtherRecordsAlone(t *testing.T) {
	for name, opts := range map[string][]Option{
		"no masked values":         nil,
		"values that do not occur": {WithMasked(maskedToken)},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, opts...).Info("connection relayed", slog.String("orig_dst", "93.184.216.34:443"), slog.Int64("n", 7))

			rec := decode(t, &buf)
			assert.Equal(t, "connection relayed", rec["message"])
			assert.Equal(t, map[string]any{"orig_dst": "93.184.216.34:443", "n": float64(7)}, rec["context"])
		})
	}
}

// The key match still applies with masking on: a sensitive key hides its
// whole value, masked value or not.
func TestWithMasked_KeepsTheKeyRedaction(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, WithMasked(maskedToken)).Info("m", slog.String("client_random", "aabb"), slog.Any("data", map[string]string{"k": maskedToken}))

	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, redactedValue, ctx["client_random"])
	assert.Equal(t, unloggableValue, ctx["data"])
	assert.NotContains(t, buf.String(), maskedToken)
}

// A rate-limited logger derived from a masking one masks too.
func TestWithMasked_LimitedLoggerMasksToo(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, WithMasked(maskedToken)).Limited(time.Minute, 10)

	l.Warn("m", slog.String("error", "echo "+maskedToken))

	assert.NotContains(t, buf.String(), maskedToken)
	assert.Equal(t, "echo "+redactedValue, decode(t, &buf)["context"].(map[string]any)["error"])
	assert.Equal(t, "echo "+redactedValue, l.Mask("echo "+maskedToken))
}

// Mask gives the text as the logger would write it, so a caller can cut a
// long text after masking it; cut first, the head of a value would stay.
func TestMask_ReturnsTheTextAsLogged(t *testing.T) {
	plain := New(&bytes.Buffer{})
	masking := New(&bytes.Buffer{}, WithMasked(maskedToken))
	text := strings.Repeat("x", 20) + maskedToken + strings.Repeat("y", 20)

	assert.Equal(t, text, plain.Mask(text))
	masked := masking.Mask(text)
	require.Equal(t, strings.Repeat("x", 20)+redactedValue+strings.Repeat("y", 20), masked)
	assert.NotContains(t, masked[:25], maskedToken[:5], "a cut after masking holds no head of the value")
	assert.Empty(t, masking.Mask(""))
}

// The text the mask compares is the text the handler writes, for every kind
// of field the logger takes: the token in the JSON line, without the quotes
// of a string.
func TestWrittenText_IsWhatTheHandlerWrites(t *testing.T) {
	berlin := time.FixedZone("CET", 3600)
	for name, v := range map[string]slog.Value{
		"string":                  slog.StringValue("plain text"),
		"int64":                   slog.Int64Value(-9223372036854775808),
		"uint64":                  slog.Uint64Value(18446744073709551615),
		"bool":                    slog.BoolValue(false),
		"float, integral":         slog.Float64Value(123456789),
		"float, fraction":         slog.Float64Value(0.1),
		"float, exponent":         slog.Float64Value(1e21),
		"float, small exponent":   slog.Float64Value(1.5e-9),
		"float, negative zero":    slog.Float64Value(-1 * 0.0),
		"duration":                slog.DurationValue(90 * time.Minute),
		"duration, negative":      slog.DurationValue(-12345678 * time.Nanosecond),
		"time, UTC, nanoseconds":  slog.TimeValue(time.Date(2026, 11, 14, 2, 7, 25, 123456789, time.UTC)),
		"time, another zone":      slog.TimeValue(time.Date(2026, 11, 14, 3, 7, 25, 120000000, berlin)),
		"time, whole second":      slog.TimeValue(time.Date(2026, 11, 14, 2, 7, 25, 0, time.UTC)),
		"error, through slog.Any": slog.AnyValue(errors.New("dial refused")),
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf).Info("m", slog.Any("v", v))

			line := buf.String()
			_, after, found := strings.Cut(line, `"context":{"v":`)
			require.True(t, found, "line: %s", line)
			written := strings.Trim(strings.TrimSuffix(strings.TrimSpace(after), "}}"), `"`)
			// What reaches the mask is the attribute as replaceAttr holds it:
			// an opaque value already flattened by scalarAttr.
			attr := slog.Any("v", v)
			if attr.Value.Kind() == slog.KindAny {
				attr = scalarAttr(attr)
			}
			assert.Equal(t, written, writtenText(attr.Value))
		})
	}
}

// Three values the handler does not write as themselves: for a float JSON
// cannot encode and a time outside years 0 to 9999 it writes an error text
// of its own, and for a nil it writes null. None of those texts carries
// anything of the caller's, and a masking logger writes them as a plain one
// does.
func TestWithMasked_LeavesTheHandlersOwnTextsAlone(t *testing.T) {
	attrs := []slog.Attr{
		slog.Float64("nan", math.NaN()),
		slog.Float64("inf", math.Inf(1)),
		slog.Time("far", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)),
		slog.Any("nil", nil),
	}
	var plain, masking bytes.Buffer
	New(&plain).Info("m", attrs...)
	New(&masking, WithMasked(maskedToken)).Info("m", attrs...)

	want := decode(t, &plain)["context"].(map[string]any)
	got := decode(t, &masking)["context"].(map[string]any)
	assert.Equal(t, want, got)
	assert.Equal(t, "!ERROR:json: unsupported value: NaN", got["nan"])
	assert.Nil(t, got["nil"])
}
