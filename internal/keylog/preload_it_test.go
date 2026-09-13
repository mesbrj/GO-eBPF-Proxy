//go:build integration

package keylog

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	buildSOOnce sync.Once
	builtSOPath string
	buildSOErr  error
)

// requirePreloadSO builds preload/keylog_preload.c fresh (once per test run)
// and returns the built .so path, skipping the calling test if no C
// compiler or system libssl is available.
func requirePreloadSO(t *testing.T) string {
	t.Helper()
	buildSOOnce.Do(func() {
		cc := ""
		for _, cand := range []string{"clang", "gcc", "cc"} {
			if _, err := exec.LookPath(cand); err == nil {
				cc = cand
				break
			}
		}
		if cc == "" {
			buildSOErr = fmt.Errorf("no C compiler (clang/gcc/cc) found in PATH")
			return
		}
		srcPath, err := filepath.Abs("../../preload/keylog_preload.c")
		if err != nil {
			buildSOErr = err
			return
		}
		dir, err := os.MkdirTemp("", "keylog-preload-build")
		if err != nil {
			buildSOErr = err
			return
		}
		out := filepath.Join(dir, "libkeylogpreload.so")
		cmd := exec.Command(cc, "-shared", "-fPIC", "-o", out, srcPath, "-ldl", "-lssl", "-lcrypto") // #nosec G204 -- fixed args, test-controlled compiler/source
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildSOErr = fmt.Errorf("build interposer .so with %s: %w: %s", cc, err, stderr.String())
			return
		}
		builtSOPath = out
	})
	if buildSOErr != nil {
		t.Skipf("cannot build LD_PRELOAD interposer: %v", buildSOErr)
	}
	return builtSOPath
}

// generateSelfSignedCert writes a throwaway self-signed cert/key pair to dir
// for a local openssl s_server instance.
func generateSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certOut.Close())

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	require.NoError(t, keyOut.Close())
	return certPath, keyPath
}

// startOpenSSLServer starts `openssl s_server` on a free loopback port,
// looping to accept connections (no -naccept limit) until stopped. It
// returns the listening address and a stop func to kill the process.
func startOpenSSLServer(t *testing.T, certPath, keyPath, tlsFlag string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	args := []string{"s_server", "-key", keyPath, "-cert", certPath, "-accept", strconv.Itoa(port), "-quiet"}
	if tlsFlag != "" {
		args = append(args, tlsFlag)
	}
	cmd := exec.Command("openssl", args...) // #nosec G204 -- fixed subcommand, test-controlled args
	require.NoError(t, cmd.Start())

	addr = fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// runOpenSSLClient runs `openssl s_client` against addr with env appended to
// the current process environment (used to set LD_PRELOAD/
// GOEBPF_PRELOAD_SOCKET), feeding empty stdin so the handshake completes and
// the client then exits on EOF.
func runOpenSSLClient(t *testing.T, addr, tlsFlag string, env []string) {
	t.Helper()
	args := []string{"s_client", "-connect", addr, "-quiet"}
	if tlsFlag != "" {
		args = append(args, tlsFlag)
	}
	cmd := exec.Command("openssl", args...) // #nosec G204 -- fixed subcommand, test-controlled args
	cmd.Stdin = strings.NewReader("")
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run() // s_client's exit code on EOF-after-handshake varies by version; the assertion is on the keylog side channel, not this process's exit status
}

// IT-02.1: a real TLS 1.3 handshake through openssl s_client, with the
// interposer LD_PRELOADed into the client, yields the sidecar's socket
// server the five TLS 1.3 NSS lines, all sharing one client_random.
func TestPreload_TLS13Handshake_EmitsFiveLinesWithMatchingClientRandom(t *testing.T) {
	so := requirePreloadSO(t)

	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)
	addr, stop := startOpenSSLServer(t, certPath, keyPath, "-tls1_3")
	defer stop()

	_, sockPath, keylogPath := newTestSocketServer(t)

	runOpenSSLClient(t, addr, "-tls1_3", PreloadEnv(so, sockPath))

	got := waitForKeylogLineCount(t, keylogPath, 5, 5*time.Second)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	require.Len(t, lines, 5, "TLS 1.3 must emit exactly the five labelled secrets")

	wantLabels := map[string]bool{
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET": false,
		"SERVER_HANDSHAKE_TRAFFIC_SECRET": false,
		"CLIENT_TRAFFIC_SECRET_0":         false,
		"SERVER_TRAFFIC_SECRET_0":         false,
		"EXPORTER_SECRET":                 false,
	}
	var clientRandom string
	for _, line := range lines {
		fields := strings.Fields(line)
		require.Len(t, fields, 3, "each NSS line must have label, client_random, secret")
		label, cr := fields[0], fields[1]
		_, known := wantLabels[label]
		assert.True(t, known, "unexpected NSS label %q", label)
		wantLabels[label] = true
		if clientRandom == "" {
			clientRandom = cr
		}
		assert.Equal(t, clientRandom, cr, "all five TLS 1.3 lines must share the same client_random")
	}
	for label, seen := range wantLabels {
		assert.True(t, seen, "missing expected TLS 1.3 label %q", label)
	}
}

// IT-02.2: a real TLS 1.2 handshake yields exactly one CLIENT_RANDOM line.
func TestPreload_TLS12Handshake_EmitsOneClientRandomLine(t *testing.T) {
	so := requirePreloadSO(t)

	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)
	addr, stop := startOpenSSLServer(t, certPath, keyPath, "-tls1_2")
	defer stop()

	_, sockPath, keylogPath := newTestSocketServer(t)

	runOpenSSLClient(t, addr, "-tls1_2", PreloadEnv(so, sockPath))

	got := waitForKeylogLineCount(t, keylogPath, 1, 5*time.Second)
	fields := strings.Fields(strings.TrimRight(got, "\n"))
	require.Len(t, fields, 3)
	assert.Equal(t, "CLIENT_RANDOM", fields[0], "TLS 1.2 must emit a single CLIENT_RANDOM line")
}

// IT-02.4: a client without the interposer preloaded produces no keylog
// lines at all, even though it completes the same TLS handshake.
func TestPreload_ClientWithoutInterposer_EmitsNoLines(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)
	addr, stop := startOpenSSLServer(t, certPath, keyPath, "-tls1_3")
	defer stop()

	_, _, keylogPath := newTestSocketServer(t)

	// No LD_PRELOAD/GOEBPF_PRELOAD_SOCKET set: real libssl, no interposer.
	runOpenSSLClient(t, addr, "-tls1_3", nil)

	time.Sleep(300 * time.Millisecond) // let any (unexpected) line arrive
	data, err := os.ReadFile(keylogPath)
	if err != nil {
		require.True(t, os.IsNotExist(err), "unexpected error reading keylog: %v", err)
		return
	}
	assert.Empty(t, string(data), "no interposer must mean no keylog lines")
}

// IT-02.5: plain (non-TLS) HTTP traffic through curl, with the interposer
// preloaded, never calls SSL_CTX_new and so emits no keylog lines.
func TestPreload_PlainTCPTraffic_EmitsNoLines(t *testing.T) {
	so := requirePreloadSO(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not installed")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, sockPath, keylogPath := newTestSocketServer(t)

	env := PreloadEnv(so, sockPath)
	cmd := exec.Command("curl", "-s", "-o", os.DevNull, srv.URL) // #nosec G204 -- fixed subcommand, test-controlled args
	cmd.Env = append(os.Environ(), env...)
	require.NoError(t, cmd.Run())

	time.Sleep(300 * time.Millisecond)
	data, err := os.ReadFile(keylogPath)
	if err != nil {
		require.True(t, os.IsNotExist(err), "unexpected error reading keylog: %v", err)
		return
	}
	assert.Empty(t, string(data), "plain (non-TLS) traffic must never emit a keylog line")
}

// IT-02.6: a binary that never calls SSL_CTX_new (never links/dlopens
// libssl) runs to completion without crashing when the interposer is
// preloaded, and emits no keylog lines.
func TestPreload_NonOpenSSLBinary_NoCrashNoLines(t *testing.T) {
	so := requirePreloadSO(t)
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("'true' binary not found")
	}

	_, sockPath, keylogPath := newTestSocketServer(t)

	cmd := exec.Command(truePath) // #nosec G204 -- fixed, no arguments
	cmd.Env = append(os.Environ(), PreloadEnv(so, sockPath)...)
	err = cmd.Run()
	assert.NoError(t, err, "a non-OpenSSL binary must run to completion without crashing")

	time.Sleep(200 * time.Millisecond)
	data, statErr := os.ReadFile(keylogPath)
	if statErr != nil {
		require.True(t, os.IsNotExist(statErr), "unexpected error reading keylog: %v", statErr)
		return
	}
	assert.Empty(t, string(data), "a binary that never calls SSL_CTX_new must emit no keylog lines")
}

// KEYLOG-08: when the interposer's socket is unreachable (no listener at
// all), it must retry briefly then silently drop the line -- never block or
// hang the app. No sidecar/socket server is started for this test at all;
// the configured socket path never exists.
func TestPreload_SocketUnreachable_ClientCompletesWithoutBlocking(t *testing.T) {
	so := requirePreloadSO(t)

	dir := t.TempDir()
	certPath, keyPath := generateSelfSignedCert(t, dir)
	addr, stop := startOpenSSLServer(t, certPath, keyPath, "-tls1_3")
	defer stop()

	unreachableSock := filepath.Join(dir, "sock", "nobody-listening.sock")

	done := make(chan struct{})
	go func() {
		runOpenSSLClient(t, addr, "-tls1_3", PreloadEnv(so, unreachableSock))
		close(done)
	}()

	select {
	case <-done:
		// Completed -- the bounded retry (3 attempts x 20ms backoff per
		// secret) must never turn into an indefinite block.
	case <-time.After(3 * time.Second):
		t.Fatal("client did not complete within 3s; an unreachable keylog socket must never block the app")
	}
}
