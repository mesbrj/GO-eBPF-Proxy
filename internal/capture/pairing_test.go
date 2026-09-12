package capture

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
