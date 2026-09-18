//go:build e2e

// Package podman holds e2e tests for the rootful app+sidecar pod harness
// (deploy/podman/pod-up.sh, pod-down.sh). Requires root + podman + kernel >= 5.10.
package podman

import (
	"encoding/json"
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
		Status string `json:"Status"`
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
