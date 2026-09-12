//go:build integration

package capture

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IT-03.3: tcpdump and the in-process gopacket backend must decrypt to
// identical application data when capturing the same live TLS flow. Needs a
// capturable interface (CAP_NET_RAW) and tshark to assert decrypted parity;
// skips cleanly otherwise. Same class of environment-limited deferral as the
// F01/F02 real end-to-end gaps recorded in .specs/STATE.md.
func TestBackendParity_TcpdumpAndGopacketDecryptIdentically(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted parity")
	}

	dir := t.TempDir()
	tcpdumpPath := filepath.Join(dir, "tcpdump.pcap")
	gopacketPath := filepath.Join(dir, "gopacket.pcapng")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	stopTd, err := startTcpdump("lo", tcpdumpPath)
	if err != nil {
		t.Skipf("tcpdump capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stopTd() }()

	stopGp, err := startGopacket("lo", gopacketPath)
	if err != nil {
		t.Skipf("gopacket capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stopGp() }()

	kw, err := os.Create(keylogPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = kw.Close() }()

	const body = "hello-from-parity-test"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, KeyLogWriter: kw}
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, body, string(respBody))

	time.Sleep(100 * time.Millisecond) // let both capture backends drain the flow
	require.NoError(t, stopTd())
	require.NoError(t, stopGp())
	require.NoError(t, kw.Close())

	tcpdumpOut, err := DecryptedAppData(tcpdumpPath, keylogPath, "http")
	require.NoError(t, err)
	gopacketOut, err := DecryptedAppData(gopacketPath, keylogPath, "http")
	require.NoError(t, err)

	assert.Contains(t, tcpdumpOut, body, "tcpdump backend must decrypt the HTTP response body")
	assert.Contains(t, gopacketOut, body, "gopacket backend must decrypt the HTTP response body")
	assert.Equal(t, tcpdumpOut, gopacketOut, "both backends must decrypt to identical application data")
}
