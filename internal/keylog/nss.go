package keylog

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TLS wire version values, as negotiated (not the ClientHello legacy_version).
const (
	TLSVersion12 uint16 = 0x0303
	TLSVersion13 uint16 = 0x0304
)

// ErrUnknownTLSVersion is returned for an unrecognised or downgraded TLS
// version; no NSS line is ever emitted for it.
var ErrUnknownTLSVersion = errors.New("keylog: unknown or downgraded TLS version")

// LabelSet is the ordered set of NSS labels a TLS version emits per handshake.
type LabelSet []Label

// tls13LabelSet is fixed: five secrets in derivation order.
var tls13LabelSet = LabelSet{
	LabelClientHandshakeTrafficSecret,
	LabelServerHandshakeTrafficSecret,
	LabelClientTrafficSecret0,
	LabelServerTrafficSecret0,
	LabelExporterSecret,
}

// Classify selects the NSS label set for a negotiated TLS version: one
// CLIENT_RANDOM line for 1.2, the five traffic/handshake/exporter secrets for
// 1.3. Any other (unknown or downgraded) version is a typed error.
func Classify(version uint16) (LabelSet, error) {
	switch version {
	case TLSVersion12:
		return LabelSet{LabelClientRandom}, nil
	case TLSVersion13:
		return tls13LabelSet, nil
	default:
		return nil, ErrUnknownTLSVersion
	}
}

// labelName is the NSS keylog line name for each Label.
var labelName = map[Label]string{
	LabelClientRandom:                 "CLIENT_RANDOM",
	LabelClientHandshakeTrafficSecret: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	LabelServerHandshakeTrafficSecret: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
	LabelClientTrafficSecret0:         "CLIENT_TRAFFIC_SECRET_0",
	LabelServerTrafficSecret0:         "SERVER_TRAFFIC_SECRET_0",
	LabelExporterSecret:               "EXPORTER_SECRET",
}

// ErrUnknownLabel is returned for a label with no known NSS line name.
var ErrUnknownLabel = errors.New("keylog: unknown secret label")

// ErrInvalidClientRandomLength is returned when client_random isn't 32 bytes.
var ErrInvalidClientRandomLength = errors.New("keylog: client_random must be 32 bytes")

// ErrInvalidSecretLength is returned when a secret's length doesn't match what
// its label allows: exactly 48 bytes for CLIENT_RANDOM (TLS 1.2 master
// secret), or 32/48 bytes for a TLS 1.3 secret (SHA-256/SHA-384 cipher hash).
var ErrInvalidSecretLength = errors.New("keylog: secret length does not match the label's cipher-hash length")

// FormatLine formats one NSS keylog line: "<LABEL> <client_random hex> <secret hex>".
func FormatLine(label Label, clientRandom, secret []byte) (string, error) {
	name, ok := labelName[label]
	if !ok {
		return "", fmt.Errorf("%w: %d", ErrUnknownLabel, label)
	}
	if len(clientRandom) != 32 {
		return "", ErrInvalidClientRandomLength
	}
	if !validSecretLen(label, len(secret)) {
		return "", fmt.Errorf("%w: %s got %d bytes", ErrInvalidSecretLength, name, len(secret))
	}
	return fmt.Sprintf("%s %s %s", name, hex.EncodeToString(clientRandom), hex.EncodeToString(secret)), nil
}

// validSecretLen reports whether n is an allowed secret length for label.
func validSecretLen(label Label, n int) bool {
	if label == LabelClientRandom {
		return n == 48
	}
	return n == 32 || n == 48
}

// ClientRandomKey returns the canonical lowercase-hex client_random, the
// stable join key used to pair a keylog line to its captured ClientHello.
func ClientRandomKey(clientRandom []byte) (string, error) {
	if len(clientRandom) != 32 {
		return "", ErrInvalidClientRandomLength
	}
	return hex.EncodeToString(clientRandom), nil
}

// labelByName is the reverse of labelName, used by ValidateLine.
var labelByName = func() map[string]Label {
	m := make(map[string]Label, len(labelName))
	for l, n := range labelName {
		m[n] = l
	}
	return m
}()

// ErrMalformedLine is returned by ValidateLine for any line that isn't a
// well-formed "<LABEL> <64-hex client_random> <hex secret>" NSS line.
var ErrMalformedLine = errors.New("keylog: malformed NSS keylog line")

// ValidateLine checks that line is a well-formed NSS keylog line: a known
// label, a 32-byte (64 hex chars) client_random, and a secret whose length is
// valid for that label. It never accepts a line that FormatLine would not
// have produced.
func ValidateLine(line string) error {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return fmt.Errorf("%w: expected 3 fields, got %d", ErrMalformedLine, len(fields))
	}
	label, ok := labelByName[fields[0]]
	if !ok {
		return fmt.Errorf("%w: unknown label %q", ErrMalformedLine, fields[0])
	}
	cr, err := hex.DecodeString(fields[1])
	if err != nil || len(cr) != 32 {
		return fmt.Errorf("%w: invalid client_random", ErrMalformedLine)
	}
	secret, err := hex.DecodeString(fields[2])
	if err != nil || !validSecretLen(label, len(secret)) {
		return fmt.Errorf("%w: invalid secret length for %s", ErrMalformedLine, fields[0])
	}
	return nil
}
