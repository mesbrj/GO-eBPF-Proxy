package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/mesbrj/GO-eBPF-Proxy/internal/shared/logger"
)

// shmDir returns a fresh directory under /dev/shm, a tmpfs on every Linux
// host this project supports, removed when the test ends.
func shmDir(t *testing.T) string {
	t.Helper()
	var st unix.Statfs_t
	require.NoError(t, unix.Statfs("/dev/shm", &st))
	require.True(t, st.Type == unix.TMPFS_MAGIC, "precondition: /dev/shm must be tmpfs, statfs reports f_type 0x%x", st.Type)
	dir, err := os.MkdirTemp("/dev/shm", "goebpf-keylog-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// offTmpfsDir returns this package's own directory in the module tree, with
// the f_type statfs reports for it. It skips only when that directory is
// itself on tmpfs, where no keylog check could be expected to refuse it.
func offTmpfsDir(t *testing.T) (string, string) {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	var st unix.Statfs_t
	require.NoError(t, unix.Statfs(dir, &st))
	if st.Type == unix.TMPFS_MAGIC {
		t.Skipf("the module tree %s is on tmpfs; no directory off tmpfs to check", dir)
	}
	return dir, fmt.Sprintf("0x%x", st.Type)
}

// C48 (AC 33, door 5): a keylog directory off tmpfs is refused, naming the
// directory and the filesystem type statfs found -- whether the directory
// exists or is still to be created under a disk-backed ancestor.
func TestCheckKeylogTmpfs_RefusesOtherFilesystems(t *testing.T) {
	dir, fType := offTmpfsDir(t)

	t.Run("existing directory", func(t *testing.T) {
		err := checkKeylogTmpfs(filepath.Join(dir, "sslkeylog.log"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errKeylogNotTmpfs)
		assert.Contains(t, err.Error(), dir, "the error must name the keylog directory")
		assert.Contains(t, err.Error(), fType, "the error must give the f_type statfs reported")
	})
	t.Run("missing directory under it", func(t *testing.T) {
		keylogDir := filepath.Join(dir, "no-such-keylog-dir", "keylog")
		err := checkKeylogTmpfs(filepath.Join(keylogDir, "sslkeylog.log"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errKeylogNotTmpfs)
		assert.Contains(t, err.Error(), keylogDir, "the error must name the keylog directory")
		assert.Contains(t, err.Error(), fType, "the error must give the f_type of the ancestor it will be created on")
		assert.NoDirExists(t, filepath.Join(dir, "no-such-keylog-dir"), "the check must not create anything")
	})
}

// C51 (AC 34): a statfs that fails for any reason other than a missing
// directory is an error naming the directory and wrapping the cause.
func TestCheckKeylogTmpfs_StatfsFailureNamesDirAndError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so statfs cannot be made to fail this way")
	}
	parent := filepath.Join(t.TempDir(), "locked")
	keylogDir := filepath.Join(parent, "keylog")
	require.NoError(t, os.MkdirAll(keylogDir, 0o700))
	require.NoError(t, os.Chmod(parent, 0))
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) }) // #nosec G302 -- restores a test directory so t.TempDir can remove it

	err := checkKeylogTmpfs(filepath.Join(keylogDir, "sslkeylog.log"))
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrPermission)
	assert.Contains(t, err.Error(), keylogDir, "the error must name the keylog directory")
	assert.NotErrorIs(t, err, errKeylogNotTmpfs, "a failed statfs found no filesystem type to refuse")
}

// C52 (AC 35, door 5): a keylog directory on tmpfs passes, and so does one
// not created yet whose nearest existing ancestor is on tmpfs -- the pod's
// keylog/ subdirectory only appears once keylog.NewWriter creates it.
func TestCheckKeylogTmpfs_AcceptsTmpfsAndMissingDirUnderIt(t *testing.T) {
	dir := shmDir(t)

	assert.NoError(t, checkKeylogTmpfs(filepath.Join(dir, "sslkeylog.log")), "an existing tmpfs directory must pass")
	assert.NoError(t, checkKeylogTmpfs(filepath.Join(dir, "a", "b", "sslkeylog.log")), "a missing directory under tmpfs must pass")
	assert.NoDirExists(t, filepath.Join(dir, "a"), "the check must not create the keylog directory")
}

// C49 (AC 33): Start refuses a keylog off tmpfs before it loads eBPF -- no
// privilege needed to see it, and nothing loaded, attached or created to
// tear down.
func TestStart_KeylogOffTmpfsFailsBeforeEBPF(t *testing.T) {
	dir, _ := offTmpfsDir(t)
	tmp := t.TempDir()
	cfg := DefaultConfig()
	cfg.CgroupPath = "/x"
	cfg.PinDir = filepath.Join(tmp, "pin")
	cfg.RelayListen = "127.0.0.1:0"
	cfg.KeylogSocketPath = filepath.Join(tmp, "sock", "keylog.sock")
	cfg.KeylogPath = filepath.Join(dir, "sslkeylog.log")
	cfg.CapturePath = filepath.Join(tmp, "sidecar", "dump.pcapng")

	a, err := Start(cfg, logger.New(io.Discard))
	if a != nil {
		_ = a.Close()
	}

	require.Error(t, err)
	assert.ErrorIs(t, err, errKeylogNotTmpfs, "Start must fail on the keylog check")
	assert.NotContains(t, err.Error(), "app: load ebpf", "the keylog check must come before loading eBPF")
	assert.NoDirExists(t, cfg.PinDir, "loading eBPF creates the pin dir, so it must not exist")
	assert.NoDirExists(t, filepath.Join(tmp, "sidecar"), "no capture must be started")
}

// C50 (AC 33, the sidecar process's exit 1): the real binary, given a keylog
// path off tmpfs, exits 1 after exactly one ERROR line naming the directory.
func TestMain_KeylogOffTmpfsExitsOneNamingDir(t *testing.T) {
	dir, _ := offTmpfsDir(t)
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "app")
	build := exec.Command("go", "build", "-o", bin, ".") // #nosec G204 -- bin is a test-generated temp path, not external input
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build the sidecar binary: %s", out)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, // #nosec G204 -- bin and every path are test-generated, not external input
		"--cgroup-path=/x",
		"--keylog-path="+filepath.Join(dir, "sslkeylog.log"),
		"--pin-dir="+filepath.Join(tmp, "pin"),
		"--relay-listen=127.0.0.1:0",
		"--keylog-socket="+filepath.Join(tmp, "sock", "keylog.sock"),
		"--capture-path="+filepath.Join(tmp, "sidecar", "dump.pcapng"),
	)
	cmd.Env = []string{} // no GOEBPF_SIDECAR_* setting leaks in from the test's environment
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "the sidecar must exit with a status; stderr: %s", stderr.String())
	assert.Equal(t, 1, exitErr.ExitCode(), "stderr: %s", stderr.String())

	var errorLines []string
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["level"] == "ERROR" {
			errorLines = append(errorLines, line)
		}
	}
	require.Len(t, errorLines, 1, "exactly one JSON ERROR line; stderr: %s", stderr.String())
	assert.Contains(t, errorLines[0], dir, "the ERROR line must name the keylog directory")
}
