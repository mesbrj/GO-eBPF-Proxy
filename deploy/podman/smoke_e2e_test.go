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
func podUpNoCleanup(t *testing.T, podName, sidecarBin string) {
	t.Helper()
	env := append(os.Environ(), "SIDECAR_BIN="+sidecarBin, "POD_NAME="+podName)
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
	keylogPath := "/var/log/sidecar/keylog/sslkeylog.log"

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
	runSmoke(t, podName)

	capturePath := volumeCapturePath(t, podName)
	sidecar := podName + "-sidecar"
	keylogPathInContainer := "/var/log/sidecar/keylog/sslkeylog.log"
	require.Eventually(t, func() bool { return execFileSize(sidecar, keylogPathInContainer) > 0 },
		5*time.Second, 100*time.Millisecond, "keylog must be populated before offline validation")

	// Copy the tmpfs keylog out to a host-visible path for tshark pairing.
	hostKeylogPath := filepath.Join(t.TempDir(), "sslkeylog.log")
	cpOut, err := exec.Command("podman", "cp", sidecar+":"+keylogPathInContainer, hostKeylogPath).CombinedOutput() // #nosec G204 -- sidecar/path are test-generated, not external input
	require.NoError(t, err, "podman cp keylog: %s", cpOut)

	out, err := capture.DecryptedAppData(capturePath, hostKeylogPath, "http")
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(out), "example", "tshark must decrypt the app's plaintext HTTP request")
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
	podUpNoCleanup(t, podNameRetain, bin)
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
