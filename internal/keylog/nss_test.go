package keylog

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func fixedBytes(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// formatLine builds the NSS keylog line "<LABEL> <client_random hex> <secret
// hex>" as a test fixture. It validates nothing itself: tests feed its output
// through ValidateLine or Writer.Append, which do.
func formatLine(label Label, clientRandom, secret []byte) string {
	return labelName[label] + " " + hex.EncodeToString(clientRandom) + " " + hex.EncodeToString(secret)
}

// UT-02.1 / UT-02.2: every NSS label is accepted under its exact line name,
// with a 32-byte (64 hex) client_random: CLIENT_RANDOM with a 48-byte (96 hex)
// master secret, and the five TLS 1.3 labels with a secret tracking the cipher
// hash (32B -> 64 hex, 48B -> 96 hex).
func TestValidateLine_AcceptsEveryLabel(t *testing.T) {
	cases := []struct {
		label      Label
		name       string
		secretLens []int
	}{
		{LabelClientRandom, "CLIENT_RANDOM", []int{48}},
		{LabelClientHandshakeTrafficSecret, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", []int{32, 48}},
		{LabelServerHandshakeTrafficSecret, "SERVER_HANDSHAKE_TRAFFIC_SECRET", []int{32, 48}},
		{LabelClientTrafficSecret0, "CLIENT_TRAFFIC_SECRET_0", []int{32, 48}},
		{LabelServerTrafficSecret0, "SERVER_TRAFFIC_SECRET_0", []int{32, 48}},
		{LabelExporterSecret, "EXPORTER_SECRET", []int{32, 48}},
	}
	cr := fixedBytes(32, 0x11)
	for _, tc := range cases {
		for _, n := range tc.secretLens {
			t.Run(fmt.Sprintf("%s/%dB", tc.name, n), func(t *testing.T) {
				line := formatLine(tc.label, cr, fixedBytes(n, 0x22))
				assert.Equal(t, tc.name, strings.Fields(line)[0])
				assert.NoError(t, ValidateLine(line))
			})
		}
	}
}

// UT-02.1 / UT-02.2: malformed lines are rejected by the validator, including
// a secret whose length doesn't fit its label (exactly 48 bytes for
// CLIENT_RANDOM, 32 or 48 for a TLS 1.3 label).
func TestValidateLine_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"too few fields":               "CLIENT_RANDOM " + strings.Repeat("ab", 32),
		"unknown label":                "NOT_A_LABEL " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48),
		"short client_random":          "CLIENT_RANDOM " + strings.Repeat("ab", 16) + " " + strings.Repeat("cd", 48),
		"wrong secret length":          "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 20),
		"CLIENT_RANDOM 32-byte secret": "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32),
		"TLS 1.3 20-byte secret":       "EXPORTER_SECRET " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 20),
		"non-hex client_random":        "CLIENT_RANDOM " + strings.Repeat("zz", 32) + " " + strings.Repeat("cd", 48),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateLine(line), ErrMalformedLine)
		})
	}
}
