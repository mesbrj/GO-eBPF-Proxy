//go:build e2e

// Package podman holds e2e tests for the rootful app+sidecar pod harness
// (deploy/podman/pod-up.sh, pod-down.sh). Requires root + podman + kernel >= 5.10.
package podman

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRootfulPodman skips unless running as root with podman on PATH --
// the MVP harness has no rootless path (feature-03 functional requirements).
func requireRootfulPodman(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires rootful podman (run as root); see feature-03 functional requirements")
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not installed")
	}
}

// buildSidecarBinary compiles cmd/app fresh so the pod always tests the
// current tree, not a stale binary. Always statically linked (CGO_ENABLED=0)
// regardless of this host's ambient Go env default, since the sidecar image
// (alpine, musl) has no glibc interpreter to exec a dynamically-linked
// binary against (mirrors Makefile's `LINK_MODE=static`).
func buildSidecarBinary(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	repoRoot := filepath.Join(wd, "..", "..")

	bin := filepath.Join(t.TempDir(), "app")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/app") // #nosec G204 -- bin is a test-generated temp path, not external input
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build sidecar binary: %s", out)
	return bin
}

// podmanInspect is the subset of `podman inspect <container>` this suite reads.
type podmanInspect struct {
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		CapAdd []string `json:"CapAdd"`
	} `json:"HostConfig"`
	State struct {
		Status   string `json:"Status"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
}

func inspectContainer(t *testing.T, name string) podmanInspect {
	t.Helper()
	out, err := exec.Command("podman", "inspect", name).Output() // #nosec G204 -- name is a test-generated container name, not external input
	require.NoError(t, err)
	var arr []podmanInspect
	require.NoError(t, json.Unmarshal(out, &arr))
	require.Len(t, arr, 1)
	return arr[0]
}

func podUp(t *testing.T, podName, sidecarBin string) {
	t.Helper()
	env := append(os.Environ(), "SIDECAR_BIN="+sidecarBin, "POD_NAME="+podName)
	up := exec.Command("./pod-up.sh")
	up.Env = env
	out, err := up.CombinedOutput()
	require.NoError(t, err, "pod-up.sh: %s", out)
	t.Cleanup(func() {
		down := exec.Command("./pod-down.sh")
		down.Env = env
		_ = down.Run()
	})
}

// podLabel returns the value of label key on the pod podName.
func podLabel(t *testing.T, podName, key string) string {
	t.Helper()
	out, err := exec.Command("podman", "pod", "inspect", podName, "--format", `{{index .Labels "`+key+`"}}`).Output() // #nosec G204 -- podName/key are test-generated, not external input
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// podExists reports whether the named pod exists: podman pod exists exits 0
// if it does and 1 if it does not.
func podExists(t *testing.T, name string) bool {
	t.Helper()
	err := exec.Command("podman", "pod", "exists", name).Run() // #nosec G204 -- name is a test-generated pod name, not external input
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false
	}
	require.NoError(t, err, "podman pod exists %s", name)
	return true
}

// podCgroupPath resolves the pod's common parent cgroup path the way
// pod-up.sh does, for asserting bpftool attachment against the same path.
// podman pod inspect's CgroupPath has no leading slash, unlike pod-up.sh's
// own POD_CGROUP resolution -- must prepend "/sys/fs/cgroup/" (with the
// separating slash) or the two paths silently diverge (e.g.
// "/sys/fs/cgroupmachine.slice/..." instead of "/sys/fs/cgroup/machine.slice/...").
func podCgroupPath(t *testing.T, podName string) string {
	t.Helper()
	out, err := exec.Command("podman", "pod", "inspect", podName, "--format", "{{.CgroupPath}}").Output() // #nosec G204 -- podName is a test-generated pod name, not external input
	require.NoError(t, err)
	return "/sys/fs/cgroup/" + strings.TrimSpace(string(out))
}

// bpftoolCgroupTree returns `bpftool cgroup tree <path>` output listing every
// program attached at or under path.
func bpftoolCgroupTree(t *testing.T, cgroupPath string) string {
	t.Helper()
	out, err := exec.Command("bpftool", "cgroup", "tree", cgroupPath).Output() // #nosec G204 -- cgroupPath is resolved from podman's own output, not external input
	require.NoError(t, err, "bpftool cgroup tree %s", cgroupPath)
	return string(out)
}

// tupleMapEntryCount counts the entries in the pinned origdst_by_tuple map --
// the observable signal for whether connect4 redirected (and recorded) a
// given outbound connection.
func tupleMapEntryCount(t *testing.T, pinDir string) int {
	t.Helper()
	out, err := exec.Command("bpftool", "-j", "map", "dump", "pinned", filepath.Join(pinDir, "origdst_by_tuple")).Output() // #nosec G204 -- pinDir is a compiled-in constant, not external input
	require.NoError(t, err, "bpftool map dump pinned origdst_by_tuple")
	var entries []json.RawMessage
	require.NoError(t, json.Unmarshal(out, &entries))
	return len(entries)
}

// IT-03.4: the pod comes up healthy with the required namespaces, caps, and
// mounts; connect4/sockops are attached at the pod parent cgroup, their maps
// are pinned, and the app container carries the LD_PRELOAD keylog interposer.
func TestPodUp_BringsUpHealthyPodWithExpectedConfig(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it4"
	podUp(t, podName, bin)

	sidecar := inspectContainer(t, podName+"-sidecar")
	assert.Equal(t, "running", sidecar.State.Status, "sidecar container must be running")
	assert.Equal(t, "1337:1337", sidecar.Config.User, "sidecar must run entirely as UID 1337")
	assert.Contains(t, sidecar.HostConfig.CapAdd, "CAP_BPF")
	assert.Contains(t, sidecar.HostConfig.CapAdd, "CAP_NET_ADMIN")
	assert.Contains(t, sidecar.HostConfig.CapAdd, "CAP_SYS_RESOURCE", "needed for cilium/ebpf's RLIMIT_MEMLOCK raise on load")

	app := inspectContainer(t, podName+"-app")
	assert.Equal(t, "running", app.State.Status, "app container must be running")

	assert.Equal(t, "0", podLabel(t, podName, "go-ebpf-proxy.retain"),
		"a pod brought up without RETAIN=1 must record go-ebpf-proxy.retain=0 for pod-down.sh (AD-019)")

	// Maps pinned (host-visible: /sys/fs/bpf is bind-mounted into the sidecar
	// at the same path). cmd/app's compiled-in default is used since pod-up.sh
	// does not override --pin-dir.
	for _, pin := range []string{
		"/sys/fs/bpf/go-ebpf-proxy/origdst_by_cookie",
		"/sys/fs/bpf/go-ebpf-proxy/origdst_by_tuple",
	} {
		_, err := os.Stat(pin)
		assert.NoErrorf(t, err, "pin %s must exist once the sidecar has loaded", pin)
	}

	// Programs attached at the pod's common parent cgroup.
	tree := bpftoolCgroupTree(t, podCgroupPath(t, podName))
	assert.Contains(t, tree, "cgroup_connect4", "connect4 must be attached at the pod parent cgroup")
	assert.Contains(t, tree, "sockops_prog", "sockops must be attached at the pod parent cgroup")

	// LD_PRELOAD keylog interposer wired into the app container (AD-010: no
	// uprobe attach, so this is the only TLS-key-extraction hook).
	var sawLDPreload bool
	for _, kv := range app.Config.Env {
		if strings.HasPrefix(kv, "LD_PRELOAD=") {
			sawLDPreload = true
			break
		}
	}
	assert.True(t, sawLDPreload, "the app container must be launched with an LD_PRELOAD env var set")
}

// IT-03.8: the sidecar's own egress (UID 1337) is never redirected by
// connect4, while the app container's egress (any other UID) is -- the
// tuple map only gains an entry for the latter. This is the behavioral proof
// of AD-002's loop avoidance, not just the UID precondition.
func TestPodUp_SidecarEgressNotRedirected(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it8"
	podUp(t, podName, bin)

	out, err := exec.Command("podman", "exec", podName+"-sidecar", "id", "-u").Output()
	require.NoError(t, err)
	assert.Equal(t, "1337", strings.TrimSpace(string(out)), "sidecar's own processes must run as UID 1337")

	pinDir := "/sys/fs/bpf/go-ebpf-proxy"
	// TEST-NET-3 (RFC 5737): reserved, never routed; connect4 fires on the
	// connect() syscall regardless of reachability, so no real traffic is sent.
	const probe = "http://203.0.113.1/"

	before := tupleMapEntryCount(t, pinDir)
	_ = exec.Command("podman", "exec", podName+"-sidecar", "wget", "--timeout=2", "-qO-", probe).Run()
	afterSidecar := tupleMapEntryCount(t, pinDir)
	assert.Equal(t, before, afterSidecar, "the sidecar's own (UID 1337) egress must not be redirected/recorded")

	_ = exec.Command("podman", "exec", podName+"-app", "wget", "--timeout=2", "-qO-", probe).Run()
	afterApp := tupleMapEntryCount(t, pinDir)
	assert.Greater(t, afterApp, afterSidecar, "the app container's egress (non-1337 UID) must be redirected and recorded")
}

// AC 1: a clean stop is a clean exit. SIGTERM runs App.Close, whose eBPF
// teardown used to remove the pin dir with os.RemoveAll as UID 1337 against
// the root-owned /sys/fs/bpf, so every graceful stop in the pod exited 1 and
// logged "app: shutdown failed".
func TestPodStop_SidecarExitsZeroOnSigterm(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-itstop"
	podUp(t, podName, bin)
	sidecar := podName + "-sidecar"

	out, err := exec.Command("podman", "stop", "-t", "30", sidecar).CombinedOutput() // #nosec G204 -- sidecar is a test-generated container name, not external input
	require.NoError(t, err, "podman stop (SIGTERM): %s", out)

	assert.Equal(t, 0, inspectContainer(t, sidecar).State.ExitCode, "SIGTERM must end the sidecar with status 0")
	logs, err := exec.Command("podman", "logs", sidecar).CombinedOutput() // #nosec G204 -- sidecar is a test-generated container name, not external input
	require.NoError(t, err)
	assert.NotContains(t, string(logs), "app: shutdown failed", "a clean stop must not log a shutdown failure")
}

// Surface (pod-up.sh exit 1): a missing sidecar binary stops pod-up.sh with
// status 1 before it creates anything.
func TestPodUp_MissingSidecarBinaryExitsOneWithoutPod(t *testing.T) {
	requireRootfulPodman(t)
	podName := "go-ebpf-proxy-itnobin"
	up := exec.Command("./pod-up.sh")
	up.Env = append(os.Environ(), "SIDECAR_BIN="+filepath.Join(t.TempDir(), "missing"), "POD_NAME="+podName)
	out, err := up.CombinedOutput()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "pod-up.sh must fail without a sidecar binary: %s", out)
	assert.Equal(t, 1, exitErr.ExitCode(), "pod-up.sh must exit 1: %s", out)
	assert.False(t, podExists(t, podName), "a failed pod-up.sh must leave no pod behind")
}
