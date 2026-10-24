//go:build integration

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// Orchestration smoke test: every wired subsystem (eBPF load+attach, relay,
// keylog socket server, capture) starts and stops cleanly, and teardown
// honours Config.Retain. Needs CAP_BPF/CAP_PERFMON + a mounted
// bpffs/cgroupfs + CAP_NET_RAW on the capture interface; skips cleanly on an
// unprivileged box.
func TestApp_StartAndCloseAllSubsystemsCleanly(t *testing.T) {
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	// t.TempDir()'s own root is 0755 (a Go testing.T quirk: its numbered
	// subdirectories are created via os.Mkdir(dir, 0777), umask-adjusted to
	// 0755), which capture.CheckTarget correctly refuses as world-accessible.
	// Use a not-yet-existing "sidecar" subdirectory instead, matching the
	// KeylogSocketPath pattern below, so capture.NewWriter creates it fresh
	// at the intended 0700 (AD-006) -- a real deployment's capture dir is
	// always pre-secured this way (e.g. pod-up.sh's volume chmod), never a
	// pre-existing world-readable directory.
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogSocketPath = filepath.Join(dir, "sock", "keylog.sock")
	cfg.RelayListen = "127.0.0.1:0"
	// The keylog must be on tmpfs (AD-023), which t.TempDir() need not be.
	cfg.KeylogPath = filepath.Join(shmDir(t), "keylog", "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(dir, "sidecar", "dump.pcapng")
	cfg.RetentionTick = 0 // deterministic test: no background ticker

	a, err := Start(cfg, logger.New(os.Stderr))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)

	require.NoError(t, a.Close())

	for _, name := range []string{"origdst_by_cookie", "origdst_by_tuple"} {
		_, statErr := os.Stat(filepath.Join(pinDir, name))
		assert.Truef(t, os.IsNotExist(statErr), "pin %s removed on close", name)
	}
	_, statErr := os.Stat(pinDir)
	assert.NoError(t, statErr, "a pin dir that existed before Start is left in place")
	_, statErr = os.Stat(cfg.CapturePath)
	assert.True(t, os.IsNotExist(statErr), "default teardown (Retain=false) must wipe the capture directory")
}

// Teardown honours --retain: artifacts survive Close when Config.Retain is set.
func TestApp_CloseWithRetainPreservesArtifacts(t *testing.T) {
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogSocketPath = filepath.Join(dir, "sock", "keylog.sock")
	cfg.RelayListen = "127.0.0.1:0"
	// The keylog must be on tmpfs (AD-023), which t.TempDir() need not be.
	cfg.KeylogPath = filepath.Join(shmDir(t), "keylog", "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(dir, "sidecar", "dump.pcapng")
	cfg.RetentionTick = 0
	cfg.Retain = true

	a, err := Start(cfg, logger.New(os.Stderr))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)

	require.NoError(t, a.Close())

	_, statErr := os.Stat(cfg.CapturePath)
	assert.NoError(t, statErr, "--retain must preserve the capture artifact")
}
