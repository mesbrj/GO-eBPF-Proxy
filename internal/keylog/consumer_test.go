package keylog

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bpf "github.com/mesbrj/GO-eBPF-Proxy/bpf"
)

// rawSecretEvent encodes a bpf.TlsKeylogSecretEvent the way the kernel emits
// it (see internal/keylog/event_test.go's encodeCEvent).
func rawSecretEvent(t *testing.T, ev bpf.TlsKeylogSecretEvent) []byte {
	t.Helper()
	buf := make([]byte, 0, secretEventSize)
	put16 := func(v uint16) {
		b := make([]byte, 2)
		binary.NativeEndian.PutUint16(b, v)
		buf = append(buf, b...)
	}
	put16(ev.Version)
	put16(ev.Label)
	buf = append(buf, ev.ClientRandom[:]...)
	buf = append(buf, ev.Secret[:]...)
	put16(ev.SecretLen)
	return buf
}

// RouteEvent decodes+formats+writes a valid event to the keylog.
func TestRouteEvent_ValidEventAppendsLine(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "sslkeylog.log"))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	ev := bpf.TlsKeylogSecretEvent{
		Label:     uint16(LabelClientRandom),
		SecretLen: 48,
	}
	for i := range ev.ClientRandom {
		ev.ClientRandom[i] = byte(i)
	}

	require.NoError(t, RouteEvent(rawSecretEvent(t, ev), w))
}

// RouteEvent drops an event carrying an unknown label rather than emitting a
// spurious/garbage keylog line.
func TestRouteEvent_UnknownLabelDropped(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "sslkeylog.log"))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	ev := bpf.TlsKeylogSecretEvent{Label: 0xFFFF, SecretLen: 48}
	err = RouteEvent(rawSecretEvent(t, ev), w)
	assert.ErrorIs(t, err, ErrUnknownLabel)
}

// RouteEvent drops a truncated/malformed event.
func TestRouteEvent_ShortEventDropped(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "sslkeylog.log"))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	err = RouteEvent([]byte{1, 2, 3}, w)
	assert.ErrorIs(t, err, ErrShortEvent)
}

// NewConsumer rejects a Layout with no secrets configured.
func TestNewConsumer_RejectsEmptyLayout(t *testing.T) {
	_, err := NewConsumer(ConsumerConfig{PID: 1, Layout: Layout{}})
	assert.ErrorIs(t, err, ErrNoSecretsConfigured)
}
