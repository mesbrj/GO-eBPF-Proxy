//go:build integration

package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/capture"
	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// Orchestration smoke test: every wired subsystem (eBPF load+attach, relay,
// keylog socket server, capture) starts and stops cleanly, and teardown
// honours Config.Retain. Needs CAP_BPF/CAP_PERFMON + a mounted
// bpffs/cgroupfs + CAP_NET_RAW on the capture interface; skips cleanly on an
// unprivileged box. C30 (AC 20): teardown without Retain deletes this run's
// capture and keeps, byte for byte, one an earlier run left in the directory.
// (Feature 07: it asserted that the whole capture directory was wiped, by
// stat-ing the fixed --capture-path, a name no run creates any more.)
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
	// Use a "sidecar" subdirectory secured 0700 instead (AD-006), as a real
	// deployment's capture dir always is (e.g. pod-up.sh's volume chmod),
	// holding a capture kept by an earlier run.
	dir := t.TempDir()
	captureDir := filepath.Join(dir, "sidecar")
	require.NoError(t, os.Mkdir(captureDir, 0o700))
	earlier := filepath.Join(captureDir, "dump-1000000000.pcapng")
	earlierBytes := []byte("a capture kept by an earlier run")
	require.NoError(t, os.WriteFile(earlier, earlierBytes, 0o600))

	cfg := DefaultConfig()
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogSocketPath = filepath.Join(dir, "sock", "keylog.sock")
	cfg.RelayListen = "127.0.0.1:0"
	// The keylog must be on tmpfs (AD-023), which t.TempDir() need not be.
	cfg.KeylogPath = filepath.Join(shmDir(t), "keylog", "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(captureDir, "dump.pcapng")
	cfg.RetentionTick = 0 // deterministic test: no background ticker

	a, err := Start(cfg, logger.New(os.Stderr))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)
	require.NotNil(t, a.capW, "precondition: capture started")
	run := a.capW.Path()
	require.FileExists(t, run, "precondition: this run's capture exists while it runs")

	require.NoError(t, a.Close())

	for _, name := range []string{"origdst_by_cookie", "origdst_by_tuple"} {
		_, statErr := os.Stat(filepath.Join(pinDir, name))
		assert.Truef(t, os.IsNotExist(statErr), "pin %s removed on close", name)
	}
	_, statErr := os.Stat(pinDir)
	assert.NoError(t, statErr, "a pin dir that existed before Start is left in place")
	assert.NoFileExists(t, run, "default teardown (Retain=false) must delete this run's capture")
	got, err := os.ReadFile(earlier) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err, "teardown must keep a capture an earlier run left")
	assert.Equal(t, earlierBytes, got, "an earlier run's capture must be kept byte for byte")
}

// C18 (AC 12): a capture directory already at --max-bytes stops only capture.
// Start succeeds, the relay and the keylog socket accept connections, and no
// capture file is created.
func TestApp_StartWithFullCaptureDirStartsEverythingButCapture(t *testing.T) {
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
	captureDir := filepath.Join(dir, "sidecar")
	require.NoError(t, os.Mkdir(captureDir, 0o700))
	cfg := DefaultConfig()
	plantCapture(t, captureDir, "dump-1000000000.pcapng", cfg.MaxBytes, time.Now())
	cfg.CgroupPath = cg
	cfg.PinDir = pinDir
	cfg.KeylogSocketPath = filepath.Join(dir, "sock", "keylog.sock")
	cfg.RelayListen = "127.0.0.1:0"
	cfg.KeylogPath = filepath.Join(shmDir(t), "keylog", "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(captureDir, "dump.pcapng")
	cfg.RetentionTick = 0

	a, err := Start(cfg, logger.New(os.Stderr))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err, "Start must succeed without room for a capture")
	t.Cleanup(func() { _ = a.Close() })

	relay, err := net.DialTimeout("tcp", a.ln.Addr().String(), 2*time.Second)
	require.NoError(t, err, "the relay listener must accept a connection")
	_ = relay.Close()
	// The relay serves it: nothing redirected this connection, so its lookup
	// is a fail-closed miss. Waiting for that lookup also keeps Close, at
	// cleanup, from closing the eBPF map while it runs.
	require.Eventually(t, func() bool { return a.resolver.Misses() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the relay must handle the accepted connection")
	keylogConn, err := net.DialTimeout("unix", cfg.KeylogSocketPath, 2*time.Second)
	require.NoError(t, err, "the keylog socket must accept a connection")
	_ = keylogConn.Close()

	assert.Equal(t, capture.StateNotStartedMaxBytes, a.captureState())
	assert.Equal(t, []string{"dump-1000000000.pcapng"}, dirNames(t, captureDir), "no capture file may be created")
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

	require.NotNil(t, a.capW, "precondition: capture started")
	run := a.capW.Path()

	require.NoError(t, a.Close())

	// (Feature 07: stat this run's capture; the fixed --capture-path is now a
	// name template, never created.)
	_, statErr := os.Stat(run)
	assert.NoError(t, statErr, "--retain must preserve the capture artifact")
}
