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
)

// realLibssl is a system libssl present on the dev/CI image; skip when
// unavailable rather than failing the suite (mirrors internal/keylog's helper).
func realLibssl(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("no system libssl.so found for ELF-backed test")
	return ""
}

// Orchestration smoke test: every wired subsystem (eBPF load+attach, relay,
// keylog consumer, capture) starts and stops cleanly, and teardown honours
// Config.Retain. Needs CAP_BPF/CAP_PERFMON + a mounted bpffs/cgroupfs +
// CAP_NET_RAW on the capture interface; skips cleanly on an unprivileged box.
func TestApp_StartAndCloseAllSubsystemsCleanly(t *testing.T) {
	lib := realLibssl(t)

	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	keylogPinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestkeylogpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keylogPinDir) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogPinDir = keylogPinDir
	cfg.TargetPID = os.Getpid()
	cfg.LibsslPath = lib
	cfg.RelayListen = "127.0.0.1:0"
	cfg.KeylogPath = filepath.Join(dir, "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(dir, "dump.pcapng")
	cfg.RetentionTick = 0 // deterministic test: no background ticker

	a, err := Start(cfg)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)

	require.NoError(t, a.Close())

	_, statErr := os.Stat(pinDir)
	assert.True(t, os.IsNotExist(statErr), "connect4/sockops pins removed on close")
	_, statErr = os.Stat(cfg.CapturePath)
	assert.True(t, os.IsNotExist(statErr), "default teardown (Retain=false) must wipe the capture directory")
}

// Teardown honours --retain: artifacts survive Close when Config.Retain is set.
func TestApp_CloseWithRetainPreservesArtifacts(t *testing.T) {
	lib := realLibssl(t)

	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })
	keylogPinDir, err := os.MkdirTemp("/sys/fs/bpf", "gotestkeylogpin-")
	if err != nil {
		t.Skipf("need privilege + mounted bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(keylogPinDir) })

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gotestcg-")
	if err != nil {
		t.Skipf("need privilege + cgroup v2: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cg) })

	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogPinDir = keylogPinDir
	cfg.TargetPID = os.Getpid()
	cfg.LibsslPath = lib
	cfg.RelayListen = "127.0.0.1:0"
	cfg.KeylogPath = filepath.Join(dir, "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(dir, "dump.pcapng")
	cfg.RetentionTick = 0
	cfg.Retain = true

	a, err := Start(cfg)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)

	require.NoError(t, a.Close())

	_, statErr := os.Stat(cfg.CapturePath)
	assert.NoError(t, statErr, "--retain must preserve the capture artifact")
}
