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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IT-03.1 (Acceptance): a real TLS 1.3 flow captured to pcapng and paired
// with its NSS keylog must decrypt to plaintext HTTP application data via
// tshark. Needs tshark and a capturable loopback interface (CAP_NET_RAW);
// skips cleanly otherwise -- same class of environment-limited deferral
// recorded for F01/F02 in .specs/STATE.md.
func TestDecryptedAppData_RealTLS13FlowDecryptsToHTTP(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	stop, err := startGopacket("lo", pcapPath)
	if err != nil {
		t.Skipf("loopback capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stop() }()

	kw, err := os.Create(keylogPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = kw.Close() }()

	const body = "hello-from-capture-test"
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

	time.Sleep(100 * time.Millisecond) // let the capture goroutine drain the flow
	require.NoError(t, stop())
	require.NoError(t, kw.Close())

	out, err := DecryptedAppData(pcapPath, keylogPath, "http")
	require.NoError(t, err)
	assert.Contains(t, out, body, "tshark must decrypt the HTTP response body")
}

// IT-03.2: a keylog that does not correspond to the captured session (as if
// generated outside the capture window, i.e. "skewed") must fail to
// decrypt -- guarding the timestamp/session-alignment invariant against
// regression.
func TestDecryptedAppData_MismatchedKeylogFailsToDecrypt(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decryption failure")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	wrongKeylogPath := filepath.Join(dir, "wrong-sslkeylog.log")

	stop, err := startGopacket("lo", pcapPath)
	if err != nil {
		t.Skipf("loopback capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stop() }()

	const body = "hello-from-capture-test"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	// Deliberately do not wire this session's real keylog (no KeyLogWriter):
	// a bogus, well-formed-but-unrelated NSS line stands in for a keylog
	// captured outside this session's window.
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	time.Sleep(100 * time.Millisecond)
	require.NoError(t, stop())

	bogusLine := "SERVER_HANDSHAKE_TRAFFIC_SECRET " + strings.Repeat("00", 32) + " " + strings.Repeat("00", 32) + "\n"
	require.NoError(t, os.WriteFile(wrongKeylogPath, []byte(bogusLine), 0o600))

	out, err := DecryptedAppData(pcapPath, wrongKeylogPath, "http")
	// tshark does not error on a non-matching keylog; decryption silently
	// fails, so the HTTP application-data never materialises.
	require.NoError(t, err)
	assert.NotContains(t, out, body, "a keylog outside the capture's session must not decrypt the flow")
}
