package keylog

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// encodeCEvent marshals a bpf.TlsKeylogSecretEvent (the generated mirror of the
// C `secret_event` struct) the way the kernel emits it, guarding against
// layout drift between the C struct and DecodeEvent.
func encodeCEvent(t *testing.T, ev bpf.TlsKeylogSecretEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ev.Version))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ev.Label))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ev.ClientRandom))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ev.Secret))
	require.NoError(t, binary.Write(&buf, binary.NativeEndian, ev.SecretLen))
	return buf.Bytes()
}

// UT-02.3: raw event bytes decode to {version,label,client_random,secret,secret_len}.
func TestDecodeEvent_MatchesCStructLayout(t *testing.T) {
	cEvent := bpf.TlsKeylogSecretEvent{
		Version:   0x0304,
		Label:     uint16(LabelExporterSecret),
		SecretLen: 32,
	}
	for i := range cEvent.ClientRandom {
		cEvent.ClientRandom[i] = byte(i)
	}
	for i := range cEvent.Secret[:32] {
		cEvent.Secret[i] = byte(0x80 + i)
	}

	ev, err := DecodeEvent(encodeCEvent(t, cEvent))
	require.NoError(t, err)

	assert.Equal(t, uint16(0x0304), ev.Version)
	assert.Equal(t, LabelExporterSecret, ev.Label)
	assert.Equal(t, uint16(32), ev.SecretLen)
	assert.Equal(t, [32]byte(cEvent.ClientRandom), ev.ClientRandom)
	assert.Equal(t, [64]byte(cEvent.Secret), ev.Secret)
}

// UT-02.3: an event shorter than the C struct is a typed error (guards drift).
func TestDecodeEvent_ShortBufferError(t *testing.T) {
	_, err := DecodeEvent(make([]byte, 10))
	assert.ErrorIs(t, err, ErrShortEvent)
}
