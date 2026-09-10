package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

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
	New(&buf).Info("connection relayed", map[string]any{
		"conn_id":  "c-123",
		"orig_dst": "93.184.216.34:443",
	})

	rec := decode(t, &buf)
	assert.Equal(t, "INFO", rec["level"])
	assert.Equal(t, "connection relayed", rec["message"])
	assert.NotEmpty(t, rec["timestamp"], "timestamp field must be present")

	ctx, ok := rec["context"].(map[string]any)
	require.True(t, ok, "context group must be present")
	assert.Equal(t, "c-123", ctx["conn_id"])
	assert.Equal(t, "93.184.216.34:443", ctx["orig_dst"])
}

func TestLevels_WarnAndError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		log   func(l *Logger)
		level string
	}{
		{"warn", func(l *Logger) { l.Warn("miss", map[string]any{"tuple": "127.0.0.1:5"}) }, "WARN"},
		{"error", func(l *Logger) { l.Error("dial failed", map[string]any{"err": "refused"}) }, "ERROR"},
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
	New(&buf).Info("secret event", map[string]any{
		"client_random": "aabb",
		"secret":        marker,
		"conn_id":       "c-9", // non-sensitive, must survive
	})

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
	New(&buf).Info("m", map[string]any{"Client_Random": "aabb", "SECRET": "x"})
	ctx := decode(t, &buf)["context"].(map[string]any)
	assert.Equal(t, redactedValue, ctx["Client_Random"])
	assert.Equal(t, redactedValue, ctx["SECRET"])
}
