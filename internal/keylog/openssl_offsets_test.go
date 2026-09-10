package keylog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UT-02.8: correct SSL_st/SSL_SESSION offsets per version.
func TestOffsets_KnownVersions(t *testing.T) {
	t.Run("1.1.1 has one CLIENT_RANDOM secret", func(t *testing.T) {
		layout, err := Offsets(OpenSSL111)
		require.NoError(t, err)
		require.Len(t, layout.Secrets, 1)
		assert.Equal(t, "CLIENT_RANDOM", layout.Secrets[0].Label)
		assert.Equal(t, uint32(48), layout.Secrets[0].Len)
	})

	t.Run("3.0 has the five TLS 1.3 secrets plus CLIENT_RANDOM", func(t *testing.T) {
		layout, err := Offsets(OpenSSL30)
		require.NoError(t, err)
		assert.Len(t, layout.Secrets, 6)
	})

	t.Run("3.x has the five TLS 1.3 secrets plus CLIENT_RANDOM", func(t *testing.T) {
		layout, err := Offsets(OpenSSL3x)
		require.NoError(t, err)
		assert.Len(t, layout.Secrets, 6)
	})
}

// UT-02.8: unknown version -> typed error (BTF/CO-RE fallback signal).
func TestOffsets_UnknownVersionTypedError(t *testing.T) {
	_, err := Offsets(OpenSSLUnknown)
	assert.ErrorIs(t, err, ErrOffsetsUnavailable)
}

// UT-02.8: version banner classification.
func TestClassifyOpenSSLVersion(t *testing.T) {
	cases := []struct {
		banner string
		want   OpenSSLVersion
	}{
		{"OpenSSL 1.1.1w  11 Sep 2023", OpenSSL111},
		{"OpenSSL 3.0.13 30 Jan 2024", OpenSSL30},
		{"OpenSSL 3.2.1 30 Jan 2024", OpenSSL3x},
		{"garbage banner", OpenSSLUnknown},
		{"OpenSSL 1.0.2 not-supported", OpenSSLUnknown},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, ClassifyOpenSSLVersion(c.banner), "banner=%q", c.banner)
	}
}
