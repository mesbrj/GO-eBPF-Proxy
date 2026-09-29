package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decode parses the single JSON log record written to buf.
func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	return rec
}

func TestInfo_EmitsJSONShape(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("connection relayed",
		slog.String("conn_id", "c-123"),
		slog.String("orig_dst", "93.184.216.34:443"),
	)

	rec := decode(t, &buf)
	assert.Equal(t, "INFO", rec["level"])
	assert.Equal(t, "connection relayed", rec["message"])
	assert.NotEmpty(t, rec["timestamp"], "timestamp field must be present")

	ctx, ok := rec["context"].(map[string]any)
	require.True(t, ok, "context group must be present")
	assert.Equal(t, "c-123", ctx["conn_id"])
	assert.Equal(t, "93.184.216.34:443", ctx["orig_dst"])
}

func TestInfo_ContextKeepsCallOrder(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("m", slog.String("zeta", "1"), slog.String("alpha", "2"), slog.String("mid", "3"))
	assert.Contains(t, buf.String(), `"context":{"zeta":"1","alpha":"2","mid":"3"}`)
}

func TestInfo_NoAttrsOmitsContext(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Warn("keylog: socket server rejected a malformed line")
	assert.NotContains(t, decode(t, &buf), "context")
}

// Caller attrs named after slog's built-in keys must pass through unchanged:
// only the top-level time and msg keys are renamed.
func TestInfo_BuiltinKeyNamesInContextNotRenamed(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("m", slog.String("time", "t"), slog.String("msg", "x"))
	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, map[string]any{"time": "t", "msg": "x"}, ctx)
}

func TestLevels_WarnAndError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		log   func(l *Logger)
		level string
	}{
		{"warn", func(l *Logger) { l.Warn("miss", slog.String("tuple", "127.0.0.1:5")) }, "WARN"},
		{"error", func(l *Logger) { l.Error("dial failed", slog.String("err", "refused")) }, "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.log(New(&buf))
			assert.Equal(t, tc.level, decode(t, &buf)["level"])
		})
	}
}

func TestRedact_SensitiveKeysNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	marker := "unique-plaintext-marker-9f8e7d"
	New(&buf).Info("secret event",
		slog.String("client_random", "aabb"),
		slog.String("secret", marker),
		slog.String("conn_id", "c-9"), // non-sensitive, must survive
	)

	// Raw output must not contain the sensitive material at all.
	assert.NotContains(t, buf.String(), marker)
	assert.NotContains(t, strings.ToLower(buf.String()), "aabb")

	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, redactedValue, ctx["secret"])
	assert.Equal(t, redactedValue, ctx["client_random"])
	assert.Equal(t, "c-9", ctx["conn_id"], "non-sensitive fields must pass through")
}

func TestRedact_KeyMatchIsCaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("m", slog.String("Client_Random", "aabb"), slog.String("SECRET", "x"))
	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, redactedValue, ctx["Client_Random"])
	assert.Equal(t, redactedValue, ctx["SECRET"])
}

// A key names a secret whatever its case or separators, and any name ending
// in "secret(s)" -- every NSS label for a TLS 1.3 secret -- is one. A name
// that only contains a sensitive word is not, or the stats line's
// keylog_lines_rejected counter would be masked.
func TestIsSensitive(t *testing.T) {
	for _, key := range []string{
		"client_random", "clientRandom", "client-random", "CLIENT_RANDOM",
		"secret", "Secrets", "master_secret", "exporter_secret", "EARLY_EXPORTER_SECRET",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "server_traffic_secret_1",
		"key", "key1", "session_key", "privateKey", "PSK", "keylog", "plaintext",
		strings.Repeat("x", 100) + "_secret", // longer than isSensitive's stack buffer
	} {
		assert.True(t, isSensitive(key), "%q names secret material", key)
	}
	for _, key := range []string{
		"keylog_lines_rejected", "origdst_lookup_miss", "secrets_written", "keyspace",
		"orig_dst", "src", "error", "conn_id", "suppressed", "context", "",
	} {
		assert.False(t, isSensitive(key), "%q names no secret", key)
	}
}

// An attr a future Logger method adds at the top level (here via slog's
// own With) is redacted and flattened like one under "context".
func TestTopLevelAttrs_RedactedAndFlattened(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.inner = l.inner.With(slog.String("secret", opaqueMarker), slog.Any("data", map[string]string{"k": opaqueMarker}))
	l.Info("m")

	assert.NotContains(t, buf.String(), opaqueMarker)
	rec := decode(t, &buf)
	assert.Equal(t, redactedValue, rec["secret"])
	assert.Equal(t, unloggableValue, rec["data"])
	assert.Equal(t, "INFO", rec["level"], "the built-in level must pass through")
}

// The timestamp is written in UTC whatever the host's zone.
func TestTimestamp_IsUTC(t *testing.T) {
	local := time.Local
	time.Local = time.FixedZone("UTC-3", -3*60*60)
	t.Cleanup(func() { time.Local = local })

	var buf bytes.Buffer
	New(&buf).Info("m")
	ts, ok := decode(t, &buf)["timestamp"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasSuffix(ts, "Z"), "timestamp %q must be in UTC", ts)
}

func TestWithLevel_DropsRecordsBelowIt(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, WithLevel(slog.LevelWarn))
	l.Info("dropped")
	assert.Empty(t, buf.String(), "an INFO record must be dropped at level WARN")

	l.Warn("kept")
	assert.Equal(t, "kept", decode(t, &buf)["message"])
}

// A sensitive key nested in a group is masked just like a top-level one.
func TestRedact_NestedGroupKey(t *testing.T) {
	var buf bytes.Buffer
	marker := "nested-secret-marker-4c3b2a"
	New(&buf).Info("m", slog.Group("tls",
		slog.String("secret", marker),
		slog.String("version", "1.3"),
	))

	assert.NotContains(t, buf.String(), marker)
	tls := decode(t, &buf)["context"].(map[string]any)["tls"].(map[string]any)
	assert.Equal(t, redactedValue, tls["secret"])
	assert.Equal(t, "1.3", tls["version"], "non-sensitive siblings must pass through")
}

// A sensitive group name masks every value under it, whatever the leaf keys.
func TestRedact_SensitiveGroupMasksContents(t *testing.T) {
	var buf bytes.Buffer
	marker := "grouped-secret-marker-7d6e5f"
	New(&buf).Info("m", slog.Group("Keylog", slog.String("line", marker)))

	assert.NotContains(t, buf.String(), marker)
	keylog := decode(t, &buf)["context"].(map[string]any)["Keylog"].(map[string]any)
	assert.Equal(t, redactedValue, keylog["line"])
}

// opaqueMarker stands in for secret material inside an opaque value: it must
// never reach the output, whatever the value's shape.
const opaqueMarker = "opaque-marker-1a2b3c"

// stringer is a struct with an exported field that is logged as its String.
type stringer struct{ Data string }

func (stringer) String() string { return "stringer-form" }

// textOnly is a TextMarshaler that is not a Stringer.
type textOnly struct{ Data string }

func (textOnly) MarshalText() ([]byte, error) { return []byte("text-form"), nil }

// badText is a TextMarshaler whose MarshalText fails.
type badText struct{ Data string }

func (badText) MarshalText() ([]byte, error) { return nil, errors.New("no text") }

// jsonObj and jsonInt emit the marker from a custom MarshalJSON, which the
// logger must never call.
type (
	jsonObj struct{}
	jsonInt int
)

func (jsonObj) MarshalJSON() ([]byte, error) { return []byte(`{"data":"` + opaqueMarker + `"}`), nil }
func (jsonInt) MarshalJSON() ([]byte, error) { return []byte(`{"data":"` + opaqueMarker + `"}`), nil }

// Named scalar types, like keylog.Label, that slog leaves as KindAny.
type (
	label   uint16
	named   string
	enabled bool
	ratio   float32
	delta   int8
)

// A value slog has no kind for is logged only as one string, number or bool;
// anything whose contents the key match cannot see is masked.
func TestOpaqueValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  any
		want any // the decoded JSON value
	}{
		{"error is written as its message", errors.New("dial refused"), "dial refused"},
		{"stringer is written as its String", stringer{Data: opaqueMarker}, "stringer-form"},
		{"text marshaler is written as its text", textOnly{Data: opaqueMarker}, "text-form"},
		{"failing text marshaler is masked", badText{Data: opaqueMarker}, unloggableValue},
		{"named uint keeps its number", label(3), float64(3)},
		{"named int keeps its number", delta(-2), float64(-2)},
		{"named float keeps its number", ratio(0.5), 0.5},
		{"named string keeps its text", named("tls13"), "tls13"},
		{"named bool keeps its value", enabled(true), true},
		{"scalar with custom JSON is written raw", jsonInt(7), float64(7)},
		{"struct with custom JSON is masked", jsonObj{}, unloggableValue},
		{"struct is masked", struct{ Data string }{opaqueMarker}, unloggableValue},
		{"map is masked", map[string]string{"data": opaqueMarker}, unloggableValue},
		{"slice is masked", []string{opaqueMarker}, unloggableValue},
		{"byte slice is masked", []byte(opaqueMarker), unloggableValue},
		{"array is masked", [1]string{opaqueMarker}, unloggableValue},
		{"pointer is masked", &struct{ Data string }{opaqueMarker}, unloggableValue},
		{"nil is null", nil, nil},
		{"nil pointer is null without calling its methods", (*stringer)(nil), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf).Info("m", slog.Any("v", tc.val))

			assert.NotContains(t, buf.String(), opaqueMarker)
			ctx := decode(t, &buf)["context"].(map[string]any)
			require.Contains(t, ctx, "v")
			assert.Equal(t, tc.want, ctx["v"])
		})
	}
}

// slog.Group's key-value form wraps each value in slog.Any, so an opaque
// value there is masked too.
func TestOpaqueValues_InGroupArgs(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("m", slog.Group("conn", "data", map[string]string{"k": opaqueMarker}, "port", 443))

	assert.NotContains(t, buf.String(), opaqueMarker)
	conn := decode(t, &buf)["context"].(map[string]any)["conn"].(map[string]any)
	assert.Equal(t, map[string]any{"data": unloggableValue, "port": float64(443)}, conn)
}

// connStats stands in for a domain type logged as several fields: LogValue
// picks the fields, and slog resolves them into attrs the key match sees.
type connStats struct {
	id     string
	up     uint64
	secret []byte
}

// LogValue exposes secret by mistake, which the key match still masks.
func (c connStats) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("conn_id", c.id),
		slog.Uint64("bytes_up", c.up),
		slog.String("secret", string(c.secret)),
	)
}

func TestLogValuer_FieldsLoggedAndRedacted(t *testing.T) {
	var buf bytes.Buffer
	marker := "logvaluer-secret-marker-5e4d3c"
	New(&buf).Info("connection closed", slog.Any("conn", connStats{id: "c-1", up: 42, secret: []byte(marker)}))

	assert.NotContains(t, buf.String(), marker)
	conn := decode(t, &buf)["context"].(map[string]any)["conn"].(map[string]any)
	assert.Equal(t, map[string]any{"conn_id": "c-1", "bytes_up": float64(42), "secret": redactedValue}, conn)
}
