package keylog

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedBytes(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// UT-02.1: CLIENT_RANDOM <cr> <ms> accepted; 64-hex client_random, 96-hex master secret.
func TestFormatLine_ClientRandomTLS12(t *testing.T) {
	cr := fixedBytes(32, 0xAB)
	ms := fixedBytes(48, 0xCD)

	line, err := FormatLine(LabelClientRandom, cr, ms)
	require.NoError(t, err)

	fields := strings.Fields(line)
	require.Len(t, fields, 3)
	assert.Equal(t, "CLIENT_RANDOM", fields[0])
	assert.Len(t, fields[1], 64, "client_random must be 64 hex chars (32 bytes)")
	assert.Len(t, fields[2], 96, "master secret must be 96 hex chars (48 bytes)")

	assert.NoError(t, ValidateLine(line), "a formatted line must validate")
}

// UT-02.1: malformed lines are rejected by the validator.
func TestValidateLine_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"too few fields":        "CLIENT_RANDOM " + strings.Repeat("ab", 32),
		"unknown label":         "NOT_A_LABEL " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48),
		"short client_random":   "CLIENT_RANDOM " + strings.Repeat("ab", 16) + " " + strings.Repeat("cd", 48),
		"wrong secret length":   "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 20),
		"non-hex client_random": "CLIENT_RANDOM " + strings.Repeat("zz", 32) + " " + strings.Repeat("cd", 48),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateLine(line), ErrMalformedLine)
		})
	}
}

// UT-02.2: TLS 1.3 emits the five labels, each with a hex length tracking the
// cipher hash (32B -> 64 hex, 48B -> 96 hex).
func TestFormatLine_TLS13FiveLabels(t *testing.T) {
	cr := fixedBytes(32, 0x11)
	labels := []Label{
		LabelClientHandshakeTrafficSecret,
		LabelServerHandshakeTrafficSecret,
		LabelClientTrafficSecret0,
		LabelServerTrafficSecret0,
		LabelExporterSecret,
	}
	wantNames := []string{
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET",
		"CLIENT_TRAFFIC_SECRET_0",
		"SERVER_TRAFFIC_SECRET_0",
		"EXPORTER_SECRET",
	}

	for i, label := range labels {
		t.Run(wantNames[i]+"/sha256", func(t *testing.T) {
			line, err := FormatLine(label, cr, fixedBytes(32, 0x22))
			require.NoError(t, err)
			fields := strings.Fields(line)
			assert.Equal(t, wantNames[i], fields[0])
			assert.Len(t, fields[2], 64)
		})
		t.Run(wantNames[i]+"/sha384", func(t *testing.T) {
			line, err := FormatLine(label, cr, fixedBytes(48, 0x33))
			require.NoError(t, err)
			fields := strings.Fields(line)
			assert.Len(t, fields[2], 96)
		})
	}
}

// UT-02.2 / UT-02.1: secret length that doesn't match the cipher-hash options is rejected.
func TestFormatLine_InvalidSecretLength(t *testing.T) {
	cr := fixedBytes(32, 0x44)
	_, err := FormatLine(LabelExporterSecret, cr, fixedBytes(20, 0x55))
	assert.ErrorIs(t, err, ErrInvalidSecretLength)
}

// UT-02.6: version classifier selects the label set; unknown/downgraded -> typed error.
func TestClassify_VersionSelectsLabelSet(t *testing.T) {
	t.Run("1.2 -> CLIENT_RANDOM", func(t *testing.T) {
		labels, err := Classify(TLSVersion12)
		require.NoError(t, err)
		assert.Equal(t, LabelSet{LabelClientRandom}, labels)
	})
	t.Run("1.3 -> five labels", func(t *testing.T) {
		labels, err := Classify(TLSVersion13)
		require.NoError(t, err)
		assert.Len(t, labels, 5)
	})
	t.Run("unknown/downgraded -> typed error, no line", func(t *testing.T) {
		_, err := Classify(0x0301) // TLS 1.0
		assert.ErrorIs(t, err, ErrUnknownTLSVersion)
	})
}

// UT-02.10: canonical client_random is a stable lowercase-hex join key.
func TestClientRandomKey_CanonicalAndStable(t *testing.T) {
	cr := fixedBytes(32, 0xFA)
	key1, err := ClientRandomKey(cr)
	require.NoError(t, err)
	key2, err := ClientRandomKey(cr)
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "same client_random must produce the same key")
	assert.Equal(t, strings.ToLower(key1), key1, "key must be canonical lowercase hex")
	assert.Len(t, key1, 64)

	_, err = ClientRandomKey(fixedBytes(16, 0xFA))
	assert.ErrorIs(t, err, ErrInvalidClientRandomLength)
}
