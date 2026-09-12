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
// current tree, not a stale binary.
func buildSidecarBinary(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	repoRoot := filepath.Join(wd, "..", "..")

	bin := filepath.Join(t.TempDir(), "app")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/app")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build sidecar binary: %s", out)
	return bin
}

// podmanInspect is the subset of `podman inspect <container>` this suite reads.
type podmanInspect struct {
	Config struct {
		User string `json:"User"`
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
	out, err := exec.Command("podman", "inspect", name).Output()
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

// IT-03.4: the pod comes up healthy with the required namespaces, caps, and
// mounts -- the precondition for connect4/sockops attach at the pod parent
// cgroup and uprobes on the app's libssl.
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
	assert.Contains(t, sidecar.HostConfig.CapAdd, "CAP_PERFMON")

	app := inspectContainer(t, podName+"-app")
	assert.Equal(t, "running", app.State.Status, "app container must be running")
}

// IT-03.8: the sidecar's own egress runs as UID 1337 -- the identity
// connect4 skips for loop avoidance (AD-002).
func TestPodUp_SidecarRunsAsUID1337(t *testing.T) {
	requireRootfulPodman(t)
	bin := buildSidecarBinary(t)
	podName := "go-ebpf-proxy-it8"
	podUp(t, podName, bin)

	out, err := exec.Command("podman", "exec", podName+"-sidecar", "id", "-u").Output()
	require.NoError(t, err)
	assert.Equal(t, "1337", strings.TrimSpace(string(out)), "sidecar's own processes must run as UID 1337")
}
