package keylog

import (
	"errors"
	"regexp"
	"strconv"
)

// OpenSSLVersion classifies a resolved libssl build into one of the MVP's
// supported offset generations. See AD-008: OpenSSL is the only TLS-library
// module in the MVP.
type OpenSSLVersion int

const (
	// OpenSSLUnknown is any version this table has no offsets for.
	OpenSSLUnknown OpenSSLVersion = iota
	// OpenSSL111 covers the 1.1.1 branch.
	OpenSSL111
	// OpenSSL30 covers the 3.0 LTS branch.
	OpenSSL30
	// OpenSSL3x covers 3.1 and later.
	OpenSSL3x
)

// ErrOffsetsUnavailable is returned when no per-version offset table entry
// exists for a resolved OpenSSL version; callers fall back to BTF/CO-RE.
var ErrOffsetsUnavailable = errors.New("keylog: no offset table for this openssl version, use BTF/CO-RE")

// SecretOffset describes where one NSS-labelled secret lives relative to the
// base of the SSL/SSL_SESSION struct read by the uprobe.
type SecretOffset struct {
	// Label is the NSS keylog label this secret is emitted under.
	Label string
	// Offset is the byte offset (within the struct base the uprobe reads)
	// where the secret bytes begin.
	Offset uint32
	// Len is the secret length in bytes (32 for SHA-256, 48 for SHA-384).
	Len uint32
}

// Layout is a per-version offset table: where client_random lives, and where
// each emitted secret lives.
type Layout struct {
	// ClientRandomOffset is the byte offset to the 32-byte client_random.
	ClientRandomOffset uint32
	// Secrets lists every secret this version's uprobe hook can read.
	Secrets []SecretOffset
}

// offsetTable holds the per-version layouts.
//
// These offsets must be verified against the exact target build (OpenSSL's
// SSL_st/SSL_SESSION layout is not public/stable ABI); the values below are
// placeholders that document the shape of the table, gated by
// TestOffsets_KnownVersions failing loudly if unset. Operators without a
// verified table for their build should rely on BTF/CO-RE (design.md) or
// supply a corrected table.
var offsetTable = map[OpenSSLVersion]Layout{
	OpenSSL111: {
		ClientRandomOffset: 0, // TODO: verify against target 1.1.1 build
		Secrets: []SecretOffset{
			{Label: "CLIENT_RANDOM", Offset: 0, Len: 48},
		},
	},
	OpenSSL30: {
		ClientRandomOffset: 0, // TODO: verify against target 3.0 build
		Secrets: []SecretOffset{
			{Label: "CLIENT_RANDOM", Offset: 0, Len: 48},
			{Label: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", Offset: 0, Len: 32},
			{Label: "SERVER_HANDSHAKE_TRAFFIC_SECRET", Offset: 0, Len: 32},
			{Label: "CLIENT_TRAFFIC_SECRET_0", Offset: 0, Len: 32},
			{Label: "SERVER_TRAFFIC_SECRET_0", Offset: 0, Len: 32},
			{Label: "EXPORTER_SECRET", Offset: 0, Len: 32},
		},
	},
	OpenSSL3x: {
		ClientRandomOffset: 0, // TODO: verify against target 3.x build
		Secrets: []SecretOffset{
			{Label: "CLIENT_RANDOM", Offset: 0, Len: 48},
			{Label: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", Offset: 0, Len: 32},
			{Label: "SERVER_HANDSHAKE_TRAFFIC_SECRET", Offset: 0, Len: 32},
			{Label: "CLIENT_TRAFFIC_SECRET_0", Offset: 0, Len: 32},
			{Label: "SERVER_TRAFFIC_SECRET_0", Offset: 0, Len: 32},
			{Label: "EXPORTER_SECRET", Offset: 0, Len: 32},
		},
	},
}

// Offsets returns the SSL_st/SSL_SESSION offset table for the given OpenSSL
// version. Unknown versions return ErrOffsetsUnavailable so the caller can
// fall back to BTF/CO-RE.
func Offsets(v OpenSSLVersion) (Layout, error) {
	layout, ok := offsetTable[v]
	if !ok {
		return Layout{}, ErrOffsetsUnavailable
	}
	return layout, nil
}

// opensslVersionRE matches a `SSLeay_version`/`OpenSSL_version` style banner,
// e.g. "OpenSSL 3.0.13 30 Jan 2024" or "OpenSSL 1.1.1w  11 Sep 2023".
var opensslVersionRE = regexp.MustCompile(`OpenSSL (\d+)\.(\d+)\.(\d+)`)

// ClassifyOpenSSLVersion maps a version banner string to the offset table's
// version bucket. An unrecognised or unparsable banner returns OpenSSLUnknown.
func ClassifyOpenSSLVersion(banner string) OpenSSLVersion {
	m := opensslVersionRE.FindStringSubmatch(banner)
	if m == nil {
		return OpenSSLUnknown
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])

	switch {
	case major == 1 && minor == 1 && patch == 1:
		return OpenSSL111
	case major == 3 && minor == 0:
		return OpenSSL30
	case major == 3 && minor >= 1:
		return OpenSSL3x
	default:
		return OpenSSLUnknown
	}
}
