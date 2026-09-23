package keylog

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// labelName is the NSS keylog line name for each Label.
var labelName = map[Label]string{
	LabelClientRandom:                 "CLIENT_RANDOM",
	LabelClientHandshakeTrafficSecret: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
	LabelServerHandshakeTrafficSecret: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
	LabelClientTrafficSecret0:         "CLIENT_TRAFFIC_SECRET_0",
	LabelServerTrafficSecret0:         "SERVER_TRAFFIC_SECRET_0",
	LabelExporterSecret:               "EXPORTER_SECRET",
}

// validSecretLen reports whether n is an allowed secret length for label:
// exactly 48 bytes for CLIENT_RANDOM (TLS 1.2 master secret), or 32/48 bytes
// for a TLS 1.3 secret (SHA-256/SHA-384 cipher hash).
func validSecretLen(label Label, n int) bool {
	if label == LabelClientRandom {
		return n == 48
	}
	return n == 32 || n == 48
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
// label, a 32-byte (64 hex chars) client_random, and a hex secret whose
// length is valid for that label. Anything else, including a line truncated
// mid-write, is rejected with ErrMalformedLine.
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
