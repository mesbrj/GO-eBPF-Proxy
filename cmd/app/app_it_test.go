//go:build integration

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/mesbrj/netloupe-tap/internal/capture"
	"github.com/mesbrj/netloupe-tap/internal/shared/logger"
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

// itConfig returns a Config for a privileged Start of every subsystem, as the
// tests above build it: fresh bpffs pins and cgroup, a 0700 capture
// directory, and the keylog under /dev/shm (AD-023). It skips on a box
// without the privilege to create them.
func itConfig(t *testing.T) Config {
	t.Helper()
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
	cfg.KeylogPath = filepath.Join(shmDir(t), "keylog", "sslkeylog.log")
	cfg.CaptureIface = "lo"
	cfg.CapturePath = filepath.Join(dir, "sidecar", "dump.pcapng")
	cfg.RetentionTick = 0
	return cfg
}

// startIT runs Start on cfg, skipping when the kernel refuses the privileged
// capture or attach.
func startIT(t *testing.T, cfg Config) *App {
	t.Helper()
	a, err := Start(cfg, logger.New(os.Stderr))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("privileged capture/attach not permitted: %v", err)
	}
	require.NoError(t, err)
	return a
}

// C44 (AC 29, at Start): a keylog file an earlier run left at --keylog-path
// is deleted before the keylog server opens its own, so this run's keylog
// starts empty.
func TestApp_StartDeletesLeftoverKeylog(t *testing.T) {
	cfg := itConfig(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(cfg.KeylogPath), 0o700))
	leftover := "CLIENT_RANDOM " + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 48) + "\n"
	require.NoError(t, os.WriteFile(cfg.KeylogPath, []byte(leftover), 0o600))

	a := startIT(t, cfg)
	t.Cleanup(func() { _ = a.Close() })

	assert.Zero(t, fileSize(t, cfg.KeylogPath), "the keylog must hold no line from an earlier run")
}

// C64 (AC 45, at Start/Close): --retain keeps this run's capture, a pcapng
// that starts with its Section Header Block, and nothing else: the keylog
// file is deleted all the same.
func TestApp_RetainKeepsOnlyThisRunsCapture(t *testing.T) {
	cfg := itConfig(t)
	cfg.Retain = true

	a := startIT(t, cfg)
	require.NotNil(t, a.capW, "precondition: capture started")
	run := a.capW.Path()
	require.FileExists(t, cfg.KeylogPath, "precondition: the keylog exists while the sidecar runs")

	require.NoError(t, a.Close())

	got, err := os.ReadFile(run) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err, "--retain must keep this run's capture")
	require.GreaterOrEqual(t, len(got), 4)
	assert.Equal(t, []byte{0x0a, 0x0d, 0x0d, 0x0a}, got[:4], "the kept capture must start with the pcapng SHB magic")
	_, err = os.Lstat(cfg.KeylogPath)
	assert.ErrorIs(t, err, fs.ErrNotExist, "--retain must never keep the keylog")
}

// C14 (AC 1, Flow hops 2 and 3): the provider Start builds is the one the
// relay it starts records into. resolve.misses is observed at every
// collection, so it is in the final push even with no traffic.
func TestApp_StartWiresRelayMetricsToTheCollector(t *testing.T) {
	c := newCollector(t, 0, false)
	cfg := itConfig(t)
	cfg.MetricsEndpoint = c.url
	cfg.MetricsInterval = time.Hour

	a := startIT(t, cfg)
	require.NoError(t, a.Close())

	assert.NotEmpty(t, c.metrics()["netloupe.tap.relay.resolve.misses"],
		"the relay Start built must record into the provider Start built")
}

// C35 (AC 31, AC 36): a collector that is down fails neither Start nor Close.
func TestApp_StartsAndStopsWithUnreachableCollector(t *testing.T) {
	cfg := itConfig(t)
	cfg.MetricsEndpoint = "http://" + closedAddr(t).String()

	a := startIT(t, cfg)

	require.NoError(t, a.Close())
}

// sidecarRun is one privileged run of the built sidecar.
type sidecarRun struct {
	cmd    *exec.Cmd
	stderr *syncBuffer
	exited chan error
}

// startSidecar builds the sidecar and starts it with every subsystem of cfg,
// plus extraArgs, in the environment env and nothing else. A run still alive
// when the test ends is killed.
func startSidecar(t *testing.T, cfg Config, env []string, extraArgs ...string) *sidecarRun {
	t.Helper()
	args := append([]string{
		"--cgroup-path=" + cfg.CgroupPath,
		"--pin-dir=" + cfg.PinDir,
		"--relay-listen=" + cfg.RelayListen,
		"--keylog-socket=" + cfg.KeylogSocketPath,
		"--keylog-path=" + cfg.KeylogPath,
		"--capture-iface=" + cfg.CaptureIface,
		"--capture-path=" + cfg.CapturePath,
	}, extraArgs...)
	r := &sidecarRun{stderr: &syncBuffer{}, exited: make(chan error, 1)}
	r.cmd = exec.Command(buildSidecar(t), args...) // #nosec G204 -- the binary and every path are test-generated, not external input
	r.cmd.Env = append([]string{}, env...)
	r.cmd.Stderr = r.stderr
	require.NoError(t, r.cmd.Start())
	t.Cleanup(func() { _ = r.cmd.Process.Kill() })
	go func() { r.exited <- r.cmd.Wait() }()
	return r
}

// logged reports whether the sidecar's log holds text so far.
func (r *sidecarRun) logged(text string) bool {
	return strings.Contains(r.stderr.String(), text)
}

// waitUntil returns once ready holds, checking every poll, or without pausing
// when poll is zero so the caller can act at the earliest moment. It skips
// the test when the sidecar exits because the kernel refused the privileged
// capture or attach, and fails it when the sidecar exits for any other reason
// or ready does not hold within 20 s. what names the awaited state.
func (r *sidecarRun) waitUntil(t *testing.T, what string, poll time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ready() {
		select {
		case err := <-r.exited:
			r.skipIfUnprivileged(t)
			t.Fatalf("the sidecar exited before it %s (%v): %s", what, err, r.stderr.String())
		default:
		}
		require.True(t, time.Now().Before(deadline), "the sidecar never %s: %s", what, r.stderr.String())
		time.Sleep(poll)
	}
}

// skipIfUnprivileged skips the test when the sidecar's log says the kernel
// refused the privileged capture or attach.
func (r *sidecarRun) skipIfUnprivileged(t *testing.T) {
	t.Helper()
	if r.logged("operation not permitted") || r.logged("permission denied") {
		t.Skipf("privileged capture/attach not permitted: %s", r.stderr.String())
	}
}

// sigterm sends the sidecar SIGTERM, waits for it to exit and returns its
// exit code, which is -1 when the signal itself killed the process.
func (r *sidecarRun) sigterm(t *testing.T) int {
	t.Helper()
	require.NoError(t, r.cmd.Process.Signal(syscall.SIGTERM))
	return r.exit(t)
}

// exit waits for the sidecar to exit and returns its exit code, which is -1
// when a signal killed the process.
func (r *sidecarRun) exit(t *testing.T) int {
	t.Helper()
	select {
	case err := <-r.exited:
		// A sidecar that exits non-zero, or dies of the signal, is reported
		// through the returned code; anything else failed the wait itself.
		var exitErr *exec.ExitError
		if err != nil && !errors.As(err, &exitErr) {
			t.Fatalf("wait for the sidecar: %v; stderr: %s", err, r.stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the sidecar did not exit: %s", r.stderr.String())
	}
	return r.cmd.ProcessState.ExitCode()
}

// C52 (AC 36, the sidecar process's exit 0): the built sidecar, started with
// every subsystem and a collector that is down, exits 0 on SIGTERM, and says
// in its log that the final push failed rather than that shutdown did.
func TestMain_SigtermExitsZeroWithUnreachableCollector(t *testing.T) {
	run := startSidecar(t, itConfig(t), nil, "--metrics-endpoint=http://"+closedAddr(t).String())
	// main installs its signal handler before Start, so the signal is safe to
	// send as soon as the sidecar logs anything from inside Start.
	run.waitUntil(t, "started its metrics", 20*time.Millisecond, func() bool { return run.logged("metrics export started") })

	code := run.sigterm(t)

	assert.Equal(t, 0, code, "the sidecar must exit 0; stderr: %s", run.stderr.String())
	assert.True(t, run.logged("metrics shutdown failed"), "stderr: %s", run.stderr.String())
	assert.False(t, run.logged("app: shutdown failed"), "stderr: %s", run.stderr.String())
}

// C62 (PR #30 review F2): a SIGTERM that arrives while Start is still running
// ends in a clean shutdown and exit 0. The signal is sent as soon as the
// sidecar has pinned its maps, the first thing Start does after its keylog
// checks, long before it returns.
func TestMain_SigtermDuringStartStillExitsZero(t *testing.T) {
	cfg := itConfig(t)
	run := startSidecar(t, cfg, nil)
	pinned := filepath.Join(cfg.PinDir, "origdst_by_tuple")
	run.waitUntil(t, "pinned its maps", 0, func() bool {
		_, err := os.Lstat(pinned)
		return err == nil
	})
	require.False(t, run.logged("capture started"), "precondition: Start is still running when the signal is sent")

	code := run.sigterm(t)

	assert.Equal(t, 0, code, "the sidecar must exit 0; stderr: %s", run.stderr.String())
	assert.True(t, run.logged("capture started"), "Start must run to its end before the signal is acted on; stderr: %s", run.stderr.String())
	assert.False(t, run.logged("app: shutdown failed"), "stderr: %s", run.stderr.String())
}

// C66 (AC 47, at the process boundary): the built sidecar, started with
// every subsystem and an endpoint variable that does not parse and carries a
// password, reports the SDK's diagnostic by its message and never prints the
// password, anywhere on stderr, before or during shutdown.
func TestMain_UnparseableEndpointVariableNeverPrintsItsPassword(t *testing.T) {
	for _, name := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		t.Run(name, func(t *testing.T) {
			run := startSidecar(t, itConfig(t), []string{name + "=http://user:ESECRET@[::1"},
				"--metrics-endpoint=http://"+closedAddr(t).String())
			run.waitUntil(t, "started capture", 20*time.Millisecond, func() bool { return run.logged("capture started") })

			code := run.sigterm(t)

			assert.Equal(t, 0, code, "stderr: %s", run.stderr.String())
			assert.True(t, run.logged(`"sdk_message":"parse url"`), "precondition: the SDK reported the variable; stderr: %s", run.stderr.String())
			assert.False(t, run.logged("ESECRET"), "stderr: %s", run.stderr.String())
		})
	}
}

// C73 (AC 43, AC 50, at the process boundary): the built sidecar, pushing to
// a collector that answers 401 with the Authorization header and then
// 100,000 more bytes in its body, logs the failed pushes with the header
// masked and the text cut. The logger main builds is the one that masks:
// nothing on stderr holds the value, and no line is the collector's to size.
func TestMain_HeaderSentBackByTheCollectorIsMaskedOnStderr(t *testing.T) {
	c := newAnsweringCollector(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid credentials: "+r.Header.Get("Authorization")+" / "+r.Header.Get("X-Api-Key")+strings.Repeat(" x", 50_000), http.StatusUnauthorized)
	})
	run := startSidecar(t, itConfig(t), []string{"OTEL_EXPORTER_OTLP_HEADERS=" + echoHeaderVar},
		"--metrics-endpoint="+c.url, "--metrics-interval=100ms")
	run.waitUntil(t, "logged a failed push", 20*time.Millisecond, func() bool { return run.logged("metrics export failed") })

	code := run.sigterm(t)

	stderr := run.stderr.String()
	assert.Equal(t, 0, code, "stderr: %s", stderr)
	require.NotEmpty(t, c.requests())
	require.Equal(t, echoBearer, c.requests()[0].header.Get("Authorization"), "precondition: the collector was sent the header")
	assert.Contains(t, stderr, "invalid credentials: ***REDACTED*** / ***REDACTED***")
	assert.Contains(t, stderr, "metrics shutdown failed")
	assert.Contains(t, stderr, " more bytes)", "the collector's 100,000 bytes are cut")
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		assert.Less(t, len(line), 2048, "a log line the collector sized: %.200q", line)
	}
	requireNoHeaderValue(t, stderr)
}

// C74 (AC 48, at the process boundary): the built sidecar, started with a
// resource variable that does not parse, exits 1 from Start with an error
// that names the variable and never the entry.
func TestMain_MalformedResourceAttributesFailTheStartWithoutTheEntry(t *testing.T) {
	run := startSidecar(t, itConfig(t), []string{"OTEL_RESOURCE_ATTRIBUTES=RSECRET-with-no-equals"},
		"--metrics-endpoint=http://"+closedAddr(t).String())

	code := run.exit(t)

	run.skipIfUnprivileged(t)
	stderr := run.stderr.String()
	assert.Equal(t, 1, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "app: start failed")
	assert.Contains(t, stderr, "OTEL_RESOURCE_ATTRIBUTES")
	assert.NotContains(t, stderr, "RSECRET")
}

// C76 (AC 52, at the process boundary): the built sidecar, pushing to a
// collector that repeats the Authorization header in bytes nobody asked for,
// reports them as a record of its own log with the header masked. Nothing
// reaches stderr past the logger: every line there is a JSON record.
func TestMain_UnsolicitedAnswerIsLoggedMaskedNotPrintedRaw(t *testing.T) {
	run := startSidecar(t, itConfig(t), []string{"OTEL_EXPORTER_OTLP_HEADERS=" + echoHeaderVar},
		"--metrics-endpoint="+unsolicitedCollector(t), "--metrics-interval=100ms")
	run.waitUntil(t, "reported the unsolicited bytes", 20*time.Millisecond, func() bool { return run.logged("go library log") })

	code := run.sigterm(t)

	stderr := run.stderr.String()
	assert.Equal(t, 0, code, "stderr: %s", stderr)
	assert.Contains(t, stderr, "Unsolicited response received")
	assert.Contains(t, stderr, "X-Echo: ***REDACTED***")
	requireNoHeaderValue(t, stderr)
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		assert.True(t, json.Valid([]byte(line)), "a line outside the JSON log: %q", line)
	}
}
