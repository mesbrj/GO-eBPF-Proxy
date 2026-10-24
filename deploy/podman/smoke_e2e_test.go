//go:build e2e

package podman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture/capturetest"
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
	env := append(envWithout("RETAIN"), "SIDECAR_BIN="+sidecarBin, "POD_NAME="+podName)
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

// volumeExists reports whether the named podman volume exists: podman volume
// exists exits 0 if it does and 1 if it does not.
func volumeExists(t *testing.T, name string) bool {
	t.Helper()
	err := exec.Command("podman", "volume", "exists", name).Run() // #nosec G204 -- name is a test-generated volume name, not external input
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false
	}
	require.NoError(t, err, "podman volume exists %s", name)
	return true
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

// tsharkTimeout bounds one tshark run. A smoke capture holds a few flows and
// dissects in seconds, so a run still going after this is wedged and should
// fail its test, not stall the suite until go test's global timeout.
const tsharkTimeout = time.Minute

// decryptAppData pairs the capture at pcapPath with keylogPath ("" pairs no
// external keylog, leaving only the capture's embedded secrets) and returns
// tshark's decrypted application data, bounded by tsharkTimeout.
func decryptAppData(t *testing.T, pcapPath, keylogPath string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), tsharkTimeout)
	defer cancel()
	return capturetest.DecryptedAppData(ctx, pcapPath, keylogPath, capturetest.AppDataFilter)
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
		out, err = decryptAppData(t, capturePath, hostKeylogPath)
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
		// RETAIN=0: the volume (a plaintext-equivalent secret once the
		// keylog is embedded in it) goes away with the pod, overriding the
		// go-ebpf-proxy.retain=1 label this RETAIN=1 pod carries (AD-019).
		down := exec.Command("./pod-down.sh")
		down.Env = append(os.Environ(), "POD_NAME="+podName, "RETAIN=0")
		_ = down.Run()
	})

	capturePath := volumeCapturePath(t, podName)
	runSmoke(t, podName)

	stopOut, err := exec.Command("podman", "stop", "-t", "30", podName+"-sidecar").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman stop sidecar (graceful, so App.Close runs): %s", stopOut)

	// No external keylog: whatever decrypts can then only have come from the
	// capture's own embedded secrets.
	out, err := decryptAppData(t, capturePath, "")
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(out), "example",
		"the capture's embedded Decryption Secrets Block must decrypt the session unaided; a DSB written after the packet blocks never can, since tshark reads a capture sequentially")
}

// IT-03.9: default teardown wipes /var/log/sidecar (the keylog tmpfs and the
// named log volume); --retain preserves the volume's artifacts. Either way the
// keylog socket volume, which holds no artifact, is removed.
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
	assert.False(t, volumeExists(t, podNameDefault+"-keylog-sock"), "default teardown must remove the keylog socket volume")

	podNameRetain := "go-ebpf-proxy-it9b"
	podUpNoCleanup(t, podNameRetain, bin, "RETAIN=1")
	capturePathRetain := volumeCapturePath(t, podNameRetain)
	downRetain := exec.Command("./pod-down.sh", "--retain")
	downRetain.Env = append(os.Environ(), "POD_NAME="+podNameRetain)
	require.NoError(t, downRetain.Run())
	_, err = os.Stat(capturePathRetain)
	assert.NoError(t, err, "--retain must preserve /var/log/sidecar")
	assert.False(t, volumeExists(t, podNameRetain+"-keylog-sock"), "--retain must still remove the keylog socket volume")

	t.Cleanup(func() {
		_ = exec.Command("podman", "volume", "rm", "-f", podNameRetain+"-sidecar-logs").Run()
	})
}

// AC 6 (AD-018): a sidecar killed without Close -- SIGKILL, as an OOM kill or
// an expired stop timeout delivers -- must still leave a capture that
// decrypts with no keylog file, for the app's TLS 1.3/HTTP2 session and its
// TLS 1.2/HTTP1.1 session alike. The keys reach the capture only through the
// interposer and the keylog socket, live, since Close never runs.
func TestSmoke_KilledSidecarCaptureSelfDecrypts(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("tshark not installed; cannot assert decrypted application data")
	}
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-itkill"
	podUpNoCleanup(t, podName, bin)
	t.Cleanup(func() {
		down := exec.Command("./pod-down.sh")
		down.Env = append(os.Environ(), "POD_NAME="+podName)
		_ = down.Run()
	})
	capturePath := volumeCapturePath(t, podName)

	h2, err := exec.Command("podman", "exec", podName+"-app", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{http_version}", // #nosec G204 -- podName is a test-generated pod name, not external input
		"--tlsv1.3", "--http2", "https://example.com").CombinedOutput()
	require.NoError(t, err, "TLS 1.3 request: %s", h2)
	require.Equal(t, "200 2", strings.TrimSpace(string(h2)), "the TLS 1.3 HTTP/2 request must succeed end-to-end")
	out, err := exec.Command("podman", "exec", podName+"-app", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", // #nosec G204 -- podName is a test-generated pod name, not external input
		"--tlsv1.2", "--tls-max", "1.2", "--http1.1", "https://example.com").CombinedOutput()
	require.NoError(t, err, "TLS 1.2 request: %s", out)
	require.Equal(t, "200", strings.TrimSpace(string(out)), "the TLS 1.2 HTTP/1.1 request must succeed end-to-end")

	time.Sleep(3 * time.Second)
	killOut, err := exec.Command("podman", "kill", "-s", "KILL", podName+"-sidecar").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman kill -s KILL sidecar: %s", killOut)

	decrypted, err := decryptAppData(t, capturePath, "")
	require.NoError(t, err)
	assert.Contains(t, decrypted, ":status: 200", "the TLS 1.3 HTTP/2 response must decrypt from the killed sidecar's capture alone")
	assert.Contains(t, decrypted, "HTTP/1.1 200 OK", "the TLS 1.2 HTTP/1.1 response must decrypt from the killed sidecar's capture alone")
}

// AC 11, AC 12 (AD-019): RETAIN=1 at pod-up.sh is the only switch. The pod
// records it, and a plain pod-down.sh then keeps what the sidecar kept.
func TestPodDown_PlainTeardownKeepsWhatPodUpRetained(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-itplain"
	podUpNoCleanup(t, podName, bin, "RETAIN=1")
	t.Cleanup(func() {
		_ = exec.Command("podman", "volume", "rm", "-f", podName+"-sidecar-logs").Run() // #nosec G204 -- podName is a test-generated pod name, not external input
	})
	assert.Equal(t, "1", podLabel(t, podName, "go-ebpf-proxy.retain"), "RETAIN=1 must be recorded on the pod")
	capturePath := volumeCapturePath(t, podName)

	down := exec.Command("./pod-down.sh")
	down.Env = append(envWithout("RETAIN"), "POD_NAME="+podName)
	out, err := down.CombinedOutput()
	require.NoError(t, err, "a plain pod-down.sh must exit 0: %s", out)
	_, err = os.Stat(capturePath)
	assert.NoError(t, err, "a plain pod-down.sh must keep the capture of a pod brought up with RETAIN=1")
}

// envWithout returns the environment minus any variable named in keys, so a
// test's own choice of e.g. RETAIN cannot be overridden by the caller's shell.
func envWithout(keys ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(keys, name) {
			env = append(env, kv)
		}
	}
	return env
}

// AC 12-16 (AD-019): pod-down.sh's retain decision, every row of pod state x
// request. Bare pods (no containers) stand in for real ones: the decision
// reads nothing but the pod's label, and its outcome shows on the pod and the
// two volumes. A refusal must leave all three untouched.
func TestPodDown_RetainDecisionTable(t *testing.T) {
	requireRootfulPodman(t)
	type outcome string
	const (
		keep   outcome = "keep"
		wipe   outcome = "wipe"
		refuse outcome = "refuse"
	)
	rows := []struct {
		pod    string // "1", "0", "unlabelled" or "missing"
		retain string // RETAIN at pod-down.sh; "" leaves it unset
		flag   bool   // --retain
		want   outcome
	}{
		{"1", "", false, keep}, {"1", "", true, keep}, {"1", "1", false, keep}, {"1", "0", false, wipe}, {"1", "0", true, keep},
		{"0", "", false, wipe}, {"0", "", true, refuse}, {"0", "1", false, refuse}, {"0", "0", false, wipe}, {"0", "0", true, refuse},
		{"unlabelled", "", false, wipe}, {"unlabelled", "", true, keep}, {"unlabelled", "1", false, keep}, {"unlabelled", "0", false, wipe},
		{"missing", "", false, wipe}, {"missing", "", true, keep}, {"missing", "1", false, keep}, {"missing", "0", false, wipe},
	}
	require.Len(t, rows, 18)
	for i, r := range rows {
		t.Run(fmt.Sprintf("pod=%s/RETAIN=%q/flag=%t", r.pod, r.retain, r.flag), func(t *testing.T) {
			podName := fmt.Sprintf("go-ebpf-proxy-ittable%02d", i)
			logVol, sockVol := podName+"-sidecar-logs", podName+"-keylog-sock"
			t.Cleanup(func() {
				_ = exec.Command("podman", "pod", "rm", "-f", podName).Run()            // #nosec G204 -- test-generated name
				_ = exec.Command("podman", "volume", "rm", "-f", logVol, sockVol).Run() // #nosec G204 -- test-generated names
			})
			for _, v := range []string{logVol, sockVol} {
				out, err := exec.Command("podman", "volume", "create", v).CombinedOutput() // #nosec G204 -- test-generated name
				require.NoError(t, err, "podman volume create %s: %s", v, out)
			}
			create := []string{"pod", "create", "--name", podName}
			switch r.pod {
			case "1", "0":
				create = append(create, "--label", "go-ebpf-proxy.retain="+r.pod)
			}
			if r.pod != "missing" {
				out, err := exec.Command("podman", create...).CombinedOutput() // #nosec G204 -- test-generated arguments
				require.NoError(t, err, "podman pod create: %s", out)
			}

			var args []string
			if r.flag {
				args = append(args, "--retain")
			}
			down := exec.Command("./pod-down.sh", args...)
			down.Env = append(envWithout("RETAIN", "POD_NAME"), "POD_NAME="+podName)
			if r.retain != "" {
				down.Env = append(down.Env, "RETAIN="+r.retain)
			}
			var stdout, stderr bytes.Buffer
			down.Stdout = &stdout
			down.Stderr = &stderr
			err := down.Run()

			switch r.want {
			case refuse:
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr, "pod-down.sh must refuse: %s", stderr.String())
				assert.Equal(t, 1, exitErr.ExitCode())
				assert.True(t, podExists(t, podName), "a refusal must leave the pod in place")
				assert.True(t, volumeExists(t, logVol), "a refusal must leave the log volume in place")
				assert.True(t, volumeExists(t, sockVol), "a refusal must leave the keylog socket volume in place")
				assert.Contains(t, stderr.String(), "RETAIN=1")
				assert.Contains(t, stderr.String(), "pod-up.sh")
				assert.Empty(t, stdout.String(), "a refusal must print nothing on stdout")
			case keep, wipe:
				require.NoError(t, err, "pod-down.sh must exit 0: %s", stderr.String())
				assert.False(t, podExists(t, podName), "the pod must be removed")
				assert.False(t, volumeExists(t, sockVol), "the keylog socket volume is always removed")
				assert.Equal(t, r.want == keep, volumeExists(t, logVol), "log volume kept must be %t", r.want == keep)
				wantLine := fmt.Sprintf("pod-down: pod %s removed, %s and %s wiped\n", podName, logVol, sockVol)
				if r.want == keep {
					wantLine = fmt.Sprintf("pod-down: retaining, keeping volume %s (%s removed)\n", logVol, sockVol)
				}
				assert.Equal(t, wantLine, stdout.String(), "pod-down.sh must print exactly its one outcome line")
			}
		})
	}
}
