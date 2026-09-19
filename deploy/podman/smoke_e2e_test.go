//go:build e2e

package podman

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture"
)

// requireInternetEgress skips when example.com isn't reachable -- the smoke
// test needs a real end-to-end TLS 1.3 request, not a stub.
func requireInternetEgress(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "example.com:443", 3*time.Second)
	if err != nil {
		t.Skipf("no internet egress to example.com: %v", err)
	}
	_ = conn.Close()
}

// podUpNoCleanup brings up the pod without registering automatic teardown,
// so a test can assert on artifacts across an explicit pod-down.sh call.
// extraEnv lets a caller pass additional env vars to pod-up.sh (e.g.
// RETAIN=1, which pod-up.sh forwards to the sidecar's own --retain flag).
func podUpNoCleanup(t *testing.T, podName, sidecarBin string, extraEnv ...string) {
	t.Helper()
	env := append(os.Environ(), "SIDECAR_BIN="+sidecarBin, "POD_NAME="+podName)
	env = append(env, extraEnv...)
	up := exec.Command("./pod-up.sh")
	up.Env = env
	out, err := up.CombinedOutput()
	require.NoError(t, err, "pod-up.sh: %s", out)
}

func runSmoke(t *testing.T, podName string) string {
	t.Helper()
	cmd := exec.Command("./smoke.sh")
	cmd.Env = append(os.Environ(), "POD_NAME="+podName)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "smoke.sh: %s", out)
	return string(out)
}

// volumeCapturePath resolves the host-visible path to the named log volume's
// dump.pcapng (the volume, unlike the keylog tmpfs, is host-visible).
func volumeCapturePath(t *testing.T, podName string) string {
	t.Helper()
	out, err := exec.Command("podman", "volume", "inspect", podName+"-sidecar-logs", "--format", "{{.Mountpoint}}").Output() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err)
	return filepath.Join(strings.TrimSpace(string(out)), "dump.pcapng")
}

// execFileSize returns the size of path inside container, or 0 if it does
// not exist yet (the keylog lives on the sidecar's tmpfs, not host-visible).
func execFileSize(container, path string) int64 {
	out, err := exec.Command("podman", "exec", container, "stat", "-c%s", path).Output() // #nosec G204 -- container/path are test-generated, not external input
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return n
}

func fileSizeOrZero(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// IT-03.5 / IT-03.6 (Acceptance, smoke test): curl https://example.com (no
// -k) from the app container succeeds end-to-end through the relay,
// validating the real server certificate, and grows the capture + keylog
// artifacts.
func TestSmoke_RealCertRequestSucceedsAndArtifactsGrow(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it56"
	podUp(t, podName, bin)

	capturePath := volumeCapturePath(t, podName)
	sizeBefore := fileSizeOrZero(capturePath)
	sidecar := podName + "-sidecar"
	keylogPath := "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log"

	out := runSmoke(t, podName)
	assert.Contains(t, out, "HTTP 200", "curl (no -k) must succeed end-to-end, validating the real cert")

	assert.Eventually(t, func() bool {
		return fileSizeOrZero(capturePath) > sizeBefore
	}, 5*time.Second, 100*time.Millisecond, "dump.pcapng must grow after the smoke request")
	assert.Eventually(t, func() bool {
		return execFileSize(sidecar, keylogPath) > 0
	}, 5*time.Second, 100*time.Millisecond, "sslkeylog.log must gain the session's lines")
}

// IT-03.7: offline validation over the harness's own produced artifacts
// decodes the app request's plaintext HTTP (the capture -> decrypt workflow).
func TestSmoke_OfflineValidationDecryptsPlaintext(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it7"
	podUp(t, podName, bin)

	capturePath := volumeCapturePath(t, podName)
	sidecar := podName + "-sidecar"
	keylogPathInContainer := "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log"
	hostKeylogPath := filepath.Join(t.TempDir(), "sslkeylog.log")

	runSmoke(t, podName)

	require.Eventually(t, func() bool { return execFileSize(sidecar, keylogPathInContainer) > 0 },
		5*time.Second, 100*time.Millisecond, "keylog must be populated before offline validation")

	// Copy the tmpfs keylog out to a host-visible path for tshark pairing.
	cpOut, err := exec.Command("podman", "cp", sidecar+":"+keylogPathInContainer, hostKeylogPath).CombinedOutput() // #nosec G204 -- sidecar/path are test-generated, not external input
	require.NoError(t, err, "podman cp keylog: %s", cpOut)

	// The capture writer flushes on a bounded interval (internal/capture's
	// flushInterval, 200ms) rather than per packet, so the response's last
	// frames can still be buffered when smoke.sh returns: give that flush a
	// bounded window to land. Note the filter must be ALPN-agnostic --
	// curl/example.com negotiate h2, which tshark's "http" dissector does not
	// match at all.
	var out string
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, err = capture.DecryptedAppData(capturePath, hostKeylogPath, capture.AppDataFilter)
		if (err == nil && strings.Contains(strings.ToLower(out), "example")) || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(out), "example",
		"pairing the harness's own capture with its own keylog must yield the request's decrypted plaintext")
}

// IT-03.7 (Acceptance, embedded DSB): the retained capture must decrypt on
// its own, with NO external keylog paired -- the "self-decrypting capture"
// the sidecar advertises. Two things make that observable: a graceful stop
// (SIGTERM -> App.Close, which is what embeds the Decryption Secrets Block;
// pod-down.sh's `pod rm -f` SIGKILLs and never gets there) and RETAIN=1, so
// that same graceful shutdown's ephemeral-by-default cleanup keeps the
// artifact instead of wiping it.
func TestSmoke_RetainedCaptureSelfDecryptsFromEmbeddedSecrets(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it7dsb"
	podUpNoCleanup(t, podName, bin, "RETAIN=1")
	t.Cleanup(func() {
		// No --retain here: the volume (a plaintext-equivalent secret once
		// the keylog is embedded in it) goes away with the pod.
		down := exec.Command("./pod-down.sh")
		down.Env = append(os.Environ(), "POD_NAME="+podName)
		_ = down.Run()
	})

	capturePath := volumeCapturePath(t, podName)
	runSmoke(t, podName)

	stopOut, err := exec.Command("podman", "stop", "-t", "30", podName+"-sidecar").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman stop sidecar (graceful, so App.Close runs): %s", stopOut)

	// An empty keylog stands in for "no keylog": whatever decrypts can then
	// only have come from the capture's own embedded secrets.
	emptyKeylog := filepath.Join(t.TempDir(), "empty-sslkeylog.log")
	require.NoError(t, os.WriteFile(emptyKeylog, nil, 0o600))

	out, err := capture.DecryptedAppData(capturePath, emptyKeylog, capture.AppDataFilter)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(out), "example",
		"the capture's embedded Decryption Secrets Block must decrypt the session unaided; a DSB written after the packet blocks never can, since tshark reads a capture sequentially")
}

// IT-03.9: default teardown wipes /var/log/sidecar (the keylog tmpfs and the
// named log volume); --retain preserves the volume's artifacts.
func TestPodDown_DefaultWipesRetainPreserves(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)

	podNameDefault := "go-ebpf-proxy-it9a"
	podUpNoCleanup(t, podNameDefault, bin)
	capturePathDefault := volumeCapturePath(t, podNameDefault)
	downDefault := exec.Command("./pod-down.sh")
	downDefault.Env = append(os.Environ(), "POD_NAME="+podNameDefault)
	require.NoError(t, downDefault.Run())
	_, err := os.Stat(capturePathDefault)
	assert.True(t, os.IsNotExist(err), "default teardown must wipe /var/log/sidecar")

	podNameRetain := "go-ebpf-proxy-it9b"
	podUpNoCleanup(t, podNameRetain, bin, "RETAIN=1")
	capturePathRetain := volumeCapturePath(t, podNameRetain)
	downRetain := exec.Command("./pod-down.sh", "--retain")
	downRetain.Env = append(os.Environ(), "POD_NAME="+podNameRetain)
	require.NoError(t, downRetain.Run())
	_, err = os.Stat(capturePathRetain)
	assert.NoError(t, err, "--retain must preserve /var/log/sidecar")

	t.Cleanup(func() {
		_ = exec.Command("podman", "volume", "rm", "-f", podNameRetain+"-sidecar-logs").Run()
	})
}
