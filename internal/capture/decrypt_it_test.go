//go:build integration

package capture

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture/capturetest"
)

// tsharkTimeout bounds one tshark run. These captures hold a single flow and
// dissect in about a second, so a run still going after this is wedged and
// should fail its test, not stall the suite until go test's global timeout.
const tsharkTimeout = time.Minute

// startLiveCapture captures iface into a fresh pcapng Writer at path through
// the sidecar's own capture path (NewWriter + StartLive), so these tests
// exercise the code the binary runs. The returned stop ends the capture and
// then closes the Writer, leaving a complete capture at path.
func startLiveCapture(iface, path string) (stop func() error, err error) {
	w, err := NewWriter(path, Options{})
	if err != nil {
		return nil, err
	}
	live, err := StartLive(iface, w)
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return func() error {
		stopErr := live.Stop() // w is written to until Stop returns
		return errors.Join(stopErr, w.Close())
	}, nil
}

// decryptAppData pairs the capture at pcapPath with keylogPath and returns
// tshark's decrypted application data, bounded by tsharkTimeout.
func decryptAppData(t *testing.T, pcapPath, keylogPath string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), tsharkTimeout)
	defer cancel()
	return capturetest.DecryptedAppData(ctx, pcapPath, keylogPath, capturetest.AppDataFilter)
}

// IT-03.1 (Acceptance): a real TLS 1.3 flow captured to pcapng and paired
// with its NSS keylog must decrypt to plaintext HTTP application data via
// tshark. Needs tshark and a capturable loopback interface (CAP_NET_RAW);
// skips cleanly otherwise -- same class of environment-limited deferral
// recorded for F01/F02 in .specs/STATE.md.
func TestOfflineDecryption_RealTLS13FlowDecryptsToHTTP(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	stop, err := startLiveCapture("lo", pcapPath)
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

	out, err := decryptAppData(t, pcapPath, keylogPath)
	require.NoError(t, err)
	assert.Contains(t, out, body, "tshark must decrypt the HTTP response body")
}

// IT-03.1 (Acceptance, ALPN coverage): the same guarantee over an HTTP/2
// session, which is what ALPN actually negotiates for any modern client and
// server (curl, Go's own transport, every browser) -- an h2 session's
// plaintext must be just as reachable as an HTTP/1.1 one's. tshark dissects
// h2 with a separate "http2" dissector that a plain "http" display filter
// never matches, so filtering on "http" alone reports zero frames for a
// perfectly captured, perfectly decrypting h2 session.
func TestOfflineDecryption_RealTLS13HTTP2FlowDecryptsToApplicationData(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	stop, err := startLiveCapture("lo", pcapPath)
	if err != nil {
		t.Skipf("loopback capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stop() }()

	kw, err := os.Create(keylogPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = kw.Close() }()

	const body = "hello-from-http2-capture-test"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, KeyLogWriter: kw}
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "HTTP/2.0", resp.Proto, "this test is only meaningful over a negotiated h2 session")
	require.Equal(t, body, string(respBody))

	time.Sleep(100 * time.Millisecond) // let the capture goroutine drain the flow
	require.NoError(t, stop())
	require.NoError(t, kw.Close())

	out, err := decryptAppData(t, pcapPath, keylogPath)
	require.NoError(t, err)
	assert.Contains(t, out, body, "tshark must decrypt the h2 response body")
}

// IT-03.1 (Acceptance, out-of-order segments): a capture that recorded the
// server's TCP segments out of sequence must still decrypt to the response
// body. This is not a hypothetical: on a real rootful Podman pod roughly a
// third of otherwise-perfect TLS 1.3 sessions land in the capture with the
// server's segments jumbled (their IP IDs prove the server sent them in
// order), and a simultaneous tcpdump -- an mmap'd AF_PACKET ring buffer --
// records exactly the same reordering, so no capture backend escapes it.
// tshark abandons TCP reassembly at the first gap unless told otherwise, and
// an abandoned stream decrypts to nothing at all, which is indistinguishable
// from lost packets or a mismatched key.
func TestOfflineDecryption_OutOfOrderServerSegmentsStillDecrypt(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	keylogPath := filepath.Join(dir, "sslkeylog.log")

	stop, err := startLiveCapture("lo", pcapPath)
	if err != nil {
		t.Skipf("loopback capture not permitted in this environment: %v", err)
	}
	defer func() { _ = stop() }()

	kw, err := os.Create(keylogPath) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = kw.Close() }()

	const body = "hello-from-out-of-order-capture-test"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, KeyLogWriter: kw}
	srv.StartTLS()
	defer srv.Close()
	serverPort := srv.Listener.Addr().(*net.TCPAddr).Port

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, body, string(respBody))

	time.Sleep(100 * time.Millisecond) // let the capture goroutine drain the flow
	require.NoError(t, stop())
	require.NoError(t, kw.Close())

	jumbled := filepath.Join(dir, "jumbled.pcapng")
	reordered := rewriteWithServerSegmentsReversed(t, pcapPath, jumbled, serverPort)
	require.GreaterOrEqual(t, reordered, 2, "the capture must hold several server segments for reordering them to mean anything")

	out, err := decryptAppData(t, jumbled, keylogPath)
	require.NoError(t, err)
	assert.Contains(t, out, body, "a capture whose server segments arrived out of sequence must still decrypt")
}

// rewriteWithServerSegmentsReversed copies the capture at src to dst with the
// server's payload-carrying segments in reverse order among themselves --
// every other packet, and every timestamp, left exactly where it was. That
// reproduces what a real capture records: ascending timestamps in file order,
// but the server's segments no longer in sequence order, with the stream's
// first segment arriving last. It returns how many segments it reordered.
func rewriteWithServerSegmentsReversed(t *testing.T, src, dst string, serverPort int) int {
	t.Helper()

	f, err := os.Open(src) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)

	type captured struct {
		ci   gopacket.CaptureInfo
		data []byte
	}
	var packets []captured
	var fromServer []int
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		packets = append(packets, captured{ci: ci, data: data})
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && int(tcp.SrcPort) == serverPort && len(tcp.Payload) > 0 {
			fromServer = append(fromServer, len(packets)-1)
		}
	}

	// Move whole frames (their lengths travel with them), then restore each
	// slot's original timestamp, so the file still reads back in ascending
	// time order -- exactly as a real out-of-order capture does.
	timestamps := make([]time.Time, len(packets))
	for i, p := range packets {
		timestamps[i] = p.ci.Timestamp
	}
	for i, j := 0, len(fromServer)-1; i < j; i, j = i+1, j-1 {
		a, b := fromServer[i], fromServer[j]
		packets[a], packets[b] = packets[b], packets[a]
	}

	w, err := NewWriter(dst, Options{LinkType: r.LinkType()})
	require.NoError(t, err)
	for i, p := range packets {
		p.ci.Timestamp = timestamps[i]
		require.NoError(t, w.WritePacket(p.ci, p.data))
	}
	require.NoError(t, w.Close())
	return len(fromServer)
}

// IT-03.2: a keylog that does not correspond to the captured session (as if
// generated outside the capture window, i.e. "skewed") must fail to
// decrypt -- guarding the timestamp/session-alignment invariant against
// regression.
func TestOfflineDecryption_MismatchedKeylogFailsToDecrypt(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decryption failure")
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "dump.pcapng")
	wrongKeylogPath := filepath.Join(dir, "wrong-sslkeylog.log")

	stop, err := startLiveCapture("lo", pcapPath)
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

	out, err := decryptAppData(t, pcapPath, wrongKeylogPath)
	// tshark does not error on a non-matching keylog; decryption silently
	// fails, so the HTTP application-data never materialises.
	require.NoError(t, err)
	assert.NotContains(t, out, body, "a keylog outside the capture's session must not decrypt the flow")
}
