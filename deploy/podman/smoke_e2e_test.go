//go:build e2e

package podman

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
// RETAIN=1, which pod-up.sh forwards to the sidecar's own --retain flag). It
// returns what pod-up.sh printed on stderr.
func podUpNoCleanup(t *testing.T, podName, sidecarBin string, extraEnv ...string) string {
	t.Helper()
	env := append(envWithout("RETAIN"), "SIDECAR_BIN="+sidecarBin, "POD_NAME="+podName)
	env = append(env, extraEnv...)
	up := exec.Command("./pod-up.sh")
	up.Env = env
	var stdout, stderr bytes.Buffer
	up.Stdout = &stdout
	up.Stderr = &stderr
	err := up.Run()
	require.NoError(t, err, "pod-up.sh: %s%s", stdout.String(), stderr.String())
	return stderr.String()
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

// volumeMountpoint resolves the host-visible directory of the named pod's log
// volume (the volume, unlike the keylog tmpfs, is host-visible).
func volumeMountpoint(t *testing.T, podName string) string {
	t.Helper()
	out, err := exec.Command("podman", "volume", "inspect", podName+"-sidecar-logs", "--format", "{{.Mountpoint}}").Output() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// volumeCapturePath resolves the host-visible path of the newest capture in
// the named pod's log volume. Each run writes its own
// dump-<epoch>[-<n>].pcapng (AD-021), so the newest is the running sidecar's,
// whatever an earlier run kept beside it.
func volumeCapturePath(t *testing.T, podName string) string {
	t.Helper()
	dir := volumeMountpoint(t, podName)
	name := newestCapture(volumeCaptures(t, dir))
	require.NotEmpty(t, name, "no dump-<epoch>[-<n>].pcapng in %s", dir)
	return filepath.Join(dir, name)
}

// captureName matches a run's capture name, capturing its epoch and suffix.
var captureName = regexp.MustCompile(`^dump-([0-9]+)(?:-([0-9]+))?\.pcapng$`)

// volumeCaptures lists the run captures in dir: regular files named
// dump-<epoch>[-<n>].pcapng.
func volumeCaptures(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && captureName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names
}

// newestCapture returns the newest of the run capture names given, "" for
// none: the highest epoch, then the highest suffix, both compared as numbers
// (decision 9). A lexical sort would put dump-<epoch>-10 before -2.
func newestCapture(names []string) string {
	var newest string
	var newestEpoch, newestSuffix uint64
	for _, name := range names {
		m := captureName.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		epoch, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue
		}
		var suffix uint64
		if m[2] != "" {
			if suffix, err = strconv.ParseUint(m[2], 10, 64); err != nil {
				continue
			}
		}
		if newest == "" || epoch > newestEpoch || epoch == newestEpoch && suffix > newestSuffix {
			newest, newestEpoch, newestSuffix = name, epoch, suffix
		}
	}
	return newest
}

// C59 (decision 9): the newest capture is picked by epoch, then suffix, as
// numbers, never by a lexical sort.
func TestNewestCapture_ComparesEpochAndSuffixNumerically(t *testing.T) {
	for _, tc := range []struct{ newer, older string }{
		{"dump-1700000000-10.pcapng", "dump-1700000000-2.pcapng"},
		{"dump-1000000000.pcapng", "dump-999999999.pcapng"},
		{"dump-1700000000-1.pcapng", "dump-1700000000.pcapng"},
	} {
		t.Run(tc.newer+" over "+tc.older, func(t *testing.T) {
			assert.Equal(t, tc.newer, newestCapture([]string{tc.newer, tc.older}))
			assert.Equal(t, tc.newer, newestCapture([]string{tc.older, tc.newer}), "the order given must not matter")
		})
	}
}

// keptCaptureVolume creates podName's log volume before pod-up.sh does,
// holding a capture an earlier run kept: a sparse dump-1000000000.pcapng of
// size bytes, an epoch from 2001. It registers a RETAIN=0 pod-down.sh at
// cleanup, which removes the pod and the volume (AD-019). It returns the kept
// capture's path.
func keptCaptureVolume(t *testing.T, podName string, size int64) string {
	t.Helper()
	out, err := exec.Command("podman", "volume", "create", podName+"-sidecar-logs").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman volume create: %s", out)
	t.Cleanup(func() {
		down := exec.Command("./pod-down.sh")
		down.Env = append(envWithout("RETAIN", "POD_NAME"), "POD_NAME="+podName, "RETAIN=0")
		_ = down.Run()
	})
	kept := filepath.Join(volumeMountpoint(t, podName), "dump-1000000000.pcapng")
	f, err := os.OpenFile(kept, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path inside a test-generated podman volume
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Truncate(kept, size))
	return kept
}

// sidecarLogs returns the named sidecar container's log: its JSON lines on
// stderr.
func sidecarLogs(t *testing.T, podName string) string {
	t.Helper()
	out, err := exec.Command("podman", "logs", podName+"-sidecar").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman logs: %s", out)
	return string(out)
}

// logLines returns the lines of logs whose message is msg, in order.
func logLines(logs, msg string) []string {
	var lines []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"message":"`+msg+`"`) {
			lines = append(lines, line)
		}
	}
	return lines
}

// fileSHA256 returns the hex sha256 of the file at path.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- path inside a test-generated podman volume
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ownedCaptureBytes sums the sizes of the run captures in dir.
func ownedCaptureBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	for _, name := range volumeCaptures(t, dir) {
		total += fileSizeOrZero(filepath.Join(dir, name))
	}
	return total
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
	}, 5*time.Second, 100*time.Millisecond, "the capture must grow after the smoke request")
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
// the sidecar advertises. Its Decryption Secrets Blocks are the ones written
// live, ahead of the packets they decrypt (AD-018); a graceful stop (SIGTERM
// -> App.Close) only drains the hold queue and never rewrites the file
// (feature 07 C34, AD-022), which this asserts too: the closed capture is the
// same file and begins with the bytes it held before the stop. RETAIN=1 keeps
// that graceful shutdown's ephemeral-by-default cleanup from wiping it.
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

	// The file only ever grows while it is live, so whatever this read sees
	// is a prefix of it, even mid-write.
	live, err := os.ReadFile(capturePath) // #nosec G304 -- path inside a test-generated podman volume
	require.NoError(t, err)
	liveInfo, err := os.Stat(capturePath)
	require.NoError(t, err)

	stopOut, err := exec.Command("podman", "stop", "-t", "30", podName+"-sidecar").CombinedOutput() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err, "podman stop sidecar (graceful, so App.Close runs): %s", stopOut)

	closed, err := os.ReadFile(capturePath) // #nosec G304 -- path inside a test-generated podman volume
	require.NoError(t, err)
	closedInfo, err := os.Stat(capturePath)
	require.NoError(t, err)
	assert.True(t, os.SameFile(liveInfo, closedInfo), "Close must not replace the capture with another file")
	require.GreaterOrEqual(t, len(closed), len(live))
	assert.True(t, bytes.Equal(live, closed[:len(live)]), "the closed capture must begin with the bytes it held before the stop")

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

// C13-C16 (AC 1, AC 4, AC 5, AC 6, AC 7, AC 37, at the boundary): a RETAIN=1
// pod whose volume already holds a kept capture leaving 64 KiB of the default
// --max-bytes. Capture stops at the limit with one WARN line, the app keeps
// being served, the capture stops growing, the sidecar still stops cleanly,
// and the stopped capture survives a plain pod-down.sh unchanged.
func TestSmoke_CaptureStopsAtMaxBytesAndPodKeepsServing(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	const maxBytes = 104_857_600 // the sidecar's default --max-bytes
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-itlimit"
	keptCaptureVolume(t, podName, maxBytes-64<<10)
	podUpNoCleanup(t, podName, bin, "RETAIN=1")
	dir := volumeMountpoint(t, podName)
	capturePath := volumeCapturePath(t, podName)
	require.NotEqual(t, "dump-1000000000.pcapng", filepath.Base(capturePath), "precondition: this run started its own capture")

	stopped := func() bool { return len(logLines(sidecarLogs(t, podName), "capture stopped: --max-bytes reached")) > 0 }
	for i := 0; i < 50 && !stopped(); i++ {
		runSmoke(t, podName)
	}
	require.True(t, stopped(), "smoke.sh traffic must fill the 64 KiB left and stop capture")

	// What was admitted before the stop is still written once its 1 s hold
	// window passes (AC 3): measure only after that.
	time.Sleep(2 * time.Second)
	sizeAtStop := fileSizeOrZero(capturePath)
	out := runSmoke(t, podName)
	assert.Contains(t, out, "HTTP 200", "the app must still be served once capture has stopped (AC 5)")
	time.Sleep(3 * time.Second)
	assert.Equal(t, sizeAtStop, fileSizeOrZero(capturePath), "the stopped capture must not grow")
	assert.LessOrEqual(t, ownedCaptureBytes(t, dir), int64(maxBytes), "the owned captures must total at most --max-bytes")

	sidecar := podName + "-sidecar"
	stopOut, err := exec.Command("podman", "stop", "-t", "30", sidecar).CombinedOutput() // #nosec G204 -- sidecar is a test-generated container name, not external input
	require.NoError(t, err, "podman stop (SIGTERM): %s", stopOut)
	assert.Equal(t, 0, inspectContainer(t, sidecar).State.ExitCode, "SIGTERM after the stop must end the sidecar with status 0 (AC 6)")
	logs := sidecarLogs(t, podName)
	assert.NotContains(t, logs, "app: shutdown failed")
	warns := logLines(logs, "capture stopped: --max-bytes reached")
	require.Len(t, warns, 1, "exactly one WARN line (AC 4)")
	assert.Contains(t, warns[0], `"level":"WARN"`)
	stats := logLines(logs, "stats")
	require.NotEmpty(t, stats, "Close must log the final stats line")
	assert.Contains(t, stats[len(stats)-1], `"capture_state":"stopped_max_bytes"`, "the final stats line must report the stop (AC 37)")
	sum := fileSHA256(t, capturePath)

	down := exec.Command("./pod-down.sh")
	down.Env = append(envWithout("RETAIN", "POD_NAME"), "POD_NAME="+podName)
	downOut, err := down.CombinedOutput()
	require.NoError(t, err, "a plain pod-down.sh: %s", downOut)
	assert.Equal(t, sum, fileSHA256(t, capturePath), "the stopped capture must be kept byte for byte (AC 7)")
}

// C31 (AC 41, AC 17, at the boundary): a kept capture survives the next
// RETAIN=1 pod on the same volume, which writes its own beside it.
func TestPodDown_RetainedCaptureSurvivesNextRetainedPod(t *testing.T) {
	requireRootfulPodman(t)
	requireInternetEgress(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-itkeep"
	t.Cleanup(func() {
		down := exec.Command("./pod-down.sh")
		down.Env = append(envWithout("RETAIN", "POD_NAME"), "POD_NAME="+podName, "RETAIN=0")
		_ = down.Run()
	})
	plainDown := func() {
		t.Helper()
		down := exec.Command("./pod-down.sh")
		down.Env = append(envWithout("RETAIN", "POD_NAME"), "POD_NAME="+podName)
		out, err := down.CombinedOutput()
		require.NoError(t, err, "a plain pod-down.sh: %s", out)
	}

	podUpNoCleanup(t, podName, bin, "RETAIN=1")
	runSmoke(t, podName)
	plainDown()
	dir := volumeMountpoint(t, podName)
	first := volumeCaptures(t, dir)
	require.Len(t, first, 1, "precondition: the first pod kept its capture")
	firstSum := fileSHA256(t, filepath.Join(dir, first[0]))

	podUpNoCleanup(t, podName, bin, "RETAIN=1")
	runSmoke(t, podName)
	plainDown()

	captures := volumeCaptures(t, dir)
	assert.Len(t, captures, 2, "the volume must hold both runs' captures: %v", captures)
	assert.Contains(t, captures, first[0])
	assert.Equal(t, firstSum, fileSHA256(t, filepath.Join(dir, first[0])), "the first capture must be unchanged byte for byte")
}
