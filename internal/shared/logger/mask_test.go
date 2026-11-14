package logger

import (
	"bytes"
	"errors"
	"log/slog"
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

// Where occurrences of two values overlap or touch, the whole run is masked:
// masking the first must not leave the tail of the second beside it.
func TestWithMasked_OverlappingOccurrencesLeaveNoPart(t *testing.T) {
	for name, tc := range map[string]struct{ text, want string }{
		"second value overlaps the first": {"<AAAABBBBCCCCDDDD>", "<" + redactedValue + ">"},
		"first value overlaps the second": {"<BBBBCCCCDDDD> and <AAAABBBBCCCC>", "<" + redactedValue + "> and <" + redactedValue + ">"},
		"touching":                        {"<AAAABBBBCCCCBBBBCCCCDDDD>", "<" + redactedValue + ">"},
		"a value overlapping itself":      {"<AAAABBBBCCCCAAAABBBBCCCC>", "<" + redactedValue + ">"},
		"apart":                           {"AAAABBBBCCCC-BBBBCCCCDDDD", redactedValue + "-" + redactedValue},
		"a part alone is not a value":     {"<AAAABBBB>", "<AAAABBBB>"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, WithMasked("AAAABBBBCCCC", "BBBBCCCCDDDD", "XYXYXYXY")).Info("m", slog.String("v", tc.text))

			assert.Equal(t, tc.want, decode(t, &buf)["context"].(map[string]any)["v"])
		})
	}

	t.Run("a value that overlaps its own next occurrence", func(t *testing.T) {
		var buf bytes.Buffer
		New(&buf, WithMasked("XYXYXYXY")).Info("m", slog.String("v", "<XYXYXYXYXY>"))

		assert.Equal(t, "<"+redactedValue+">", decode(t, &buf)["context"].(map[string]any)["v"])
	})
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
