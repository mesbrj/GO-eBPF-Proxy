//go:build integration

package keylog

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// IT-02.4: a --libssl override attaches the uprobe to the given path even
// though this test binary (no cgo) has no libssl mapped in its own /proc/self/maps.
func TestConsumer_AttachAndCloseLifecycle(t *testing.T) {
	lib := realLibssl(t)

	cfg := ConsumerConfig{
		PID:            os.Getpid(),
		LibsslOverride: lib,
		PinDir:         filepath.Join(t.TempDir(), "pins"),
		Layout: Layout{
			ClientRandomOffset: 0,
			Secrets:            []SecretOffset{{Label: "CLIENT_RANDOM", Offset: 0, Len: 48}},
		},
		TLSVersion: TLSVersion12,
		KeylogPath: filepath.Join(t.TempDir(), "sslkeylog.log"),
	}

	c, err := NewConsumer(cfg)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("eBPF/uprobe attach not permitted (unprivileged): %v", err)
	}
	require.NoError(t, err)

	require.NoError(t, c.Close())
	_, statErr := os.Stat(cfg.PinDir)
	assert.True(t, os.IsNotExist(statErr), "pin dir removed on close")
}

// IT-02.6: no false output — an unknown/garbage label never reaches the keylog
// even when routed through the full decode->classify->format->write path.
func TestConsumer_NoFalseOutputForUnknownLabel(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "sslkeylog.log"))
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	garbage := make([]byte, secretEventSize)
	assert.Error(t, RouteEvent(garbage, w), "an all-zero/garbage event's label must not resolve to a real line")
}
