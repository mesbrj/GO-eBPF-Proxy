package capturetest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UT-03.4 / CAPTURE-05: TsharkArgs must emit the exact
// "-o tls.keylog_file:<path>" pairing invocation (spec.md P1 "Offline
// decryption pairing" AC3).
func TestTsharkArgs_EmitsCorrectKeylogPairing(t *testing.T) {
	got := TsharkArgs("/var/log/sidecar/dump.pcap", "/var/log/sidecar/sslkeylog.log")
	assert.Equal(t, []string{
		"-r", "/var/log/sidecar/dump.pcap",
		"-o", "tls.keylog_file:/var/log/sidecar/sslkeylog.log",
	}, got)
}

// Without a keylog, the option must still be emitted -- empty -- so a keylog
// in the invoking user's Wireshark preferences can never stand in for the
// capture's own embedded secrets.
func TestTsharkArgs_EmptyKeylogClearsPreference(t *testing.T) {
	got := TsharkArgs("/var/log/sidecar/dump.pcapng", "")
	assert.Equal(t, []string{
		"-r", "/var/log/sidecar/dump.pcapng",
		"-o", "tls.keylog_file:",
	}, got)
}

// A done context must surface as its own cause, not as whatever the killed
// or never-started tshark process reports -- tshark need not be installed.
func TestDecryptedAppData_CanceledContextReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := DecryptedAppData(ctx, "dump.pcapng", "sslkeylog.log", AppDataFilter)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
