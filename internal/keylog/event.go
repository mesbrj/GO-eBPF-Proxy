package keylog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Label identifies which NSS keylog line a secret event carries.
type Label uint16

// Label values mirror the NSS keylog line names; see internal/keylog/nss.go.
const (
	LabelClientRandom Label = iota // TLS 1.2 "CLIENT_RANDOM" (48-byte master secret)
	LabelClientHandshakeTrafficSecret
	LabelServerHandshakeTrafficSecret
	LabelClientTrafficSecret0
	LabelServerTrafficSecret0
	LabelExporterSecret
)

// SecretEvent is the decoded form of a bpf/tls_keylog.bpf.c `secret_event`
// ring-buffer record.
type SecretEvent struct {
	Version      uint16
	Label        Label
	ClientRandom [32]byte
	Secret       [64]byte
	SecretLen    uint16
}

// secretEventSize is sizeof(struct secret_event) in bpf/tls_keylog.bpf.c:
// 2 (version) + 2 (label) + 32 (client_random) + 64 (secret) + 2 (secret_len).
const secretEventSize = 2 + 2 + 32 + 64 + 2

// ErrShortEvent is returned when a raw ring-buffer record is smaller than the
// C `secret_event` struct, signalling a layout mismatch (CO-RE drift).
var ErrShortEvent = errors.New("keylog: ring buffer event shorter than secret_event")

// DecodeEvent decodes a raw ring-buffer record into a SecretEvent. The byte
// layout must match bpf/tls_keylog.bpf.c's `secret_event` exactly.
func DecodeEvent(raw []byte) (SecretEvent, error) {
	if len(raw) < secretEventSize {
		return SecretEvent{}, fmt.Errorf("%w: got %d bytes, want %d", ErrShortEvent, len(raw), secretEventSize)
	}
	var ev SecretEvent
	if err := binary.Read(bytes.NewReader(raw[:secretEventSize]), binary.NativeEndian, &ev); err != nil {
		return SecretEvent{}, fmt.Errorf("keylog: decode secret_event: %w", err)
	}
	return ev, nil
}
