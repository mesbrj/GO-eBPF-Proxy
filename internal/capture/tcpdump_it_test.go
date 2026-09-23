//go:build integration

package capture

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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

	stopGp, err := startLiveCapture("lo", gopacketPath)
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
	if err := stopTd(); err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			// Some hosts confine tcpdump with a security policy (e.g. an
			// AppArmor profile) that denies signal delivery from another
			// process even when that process is root -- surfaces as
			// EACCES ("permission denied"), not EPERM, on this kind of LSM
			// denial. A host security policy this package cannot and
			// should not override. Same class of environment-limited
			// deferral as the CAP_BPF/tshark skips elsewhere in this file.
			t.Skipf("cannot signal tcpdump to stop in this environment (host security policy denies it): %v", err)
		}
		require.NoError(t, err)
	}
	require.NoError(t, stopGp())
	require.NoError(t, kw.Close())

	tcpdumpOut, err := decryptAppData(t, tcpdumpPath, keylogPath)
	require.NoError(t, err)
	gopacketOut, err := decryptAppData(t, gopacketPath, keylogPath)
	require.NoError(t, err)

	assert.Contains(t, tcpdumpOut, body, "tcpdump backend must decrypt the HTTP response body")
	assert.Contains(t, gopacketOut, body, "gopacket backend must decrypt the HTTP response body")
	assert.Equal(t, tcpdumpOut, gopacketOut, "both backends must decrypt to identical application data")
}

// startTcpdump runs `tcpdump -i <iface> -w <path>` as a subprocess and
// returns a stop func that signals it to exit and waits for a clean pcap
// trailer to be flushed. tcpdump is not a sidecar backend -- the sidecar
// always captures in-process via StartLive -- only the independent reference
// the parity test above compares StartLive's capture against.
func startTcpdump(iface, path string) (stop func() error, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("capture: create capture dir: %w", err)
	}
	cmd := exec.Command("tcpdump", "-i", iface, "-w", path, "-U") // #nosec G204 -- iface/path are test-controlled, not raw user input
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("capture: start tcpdump: %w", err)
	}
	return func() error {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return fmt.Errorf("capture: stop tcpdump: %w", err)
		}
		return cmd.Wait()
	}, nil
}
