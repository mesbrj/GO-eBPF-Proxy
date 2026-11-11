package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// load runs loadConfig on a fresh flag set, as main does on flag.CommandLine,
// with environ standing in for the process environment.
func load(t *testing.T, args, environ []string) (Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return loadConfig(fs, args, environ)
}

// writeConfig writes body to a file called name in a fresh temp dir and
// returns its path.
func writeConfig(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// everySetting has a non-default value for all 13 settings, so a source
// that drops or mistypes any one of them fails the comparison.
var everySetting = Config{
	CgroupPath:       "/sys/fs/cgroup/machine.slice/pod",
	RelayListen:      "127.0.0.1:16001",
	PinDir:           "/sys/fs/bpf/other",
	KeylogSocketPath: "/run/keylog/keylog.sock",
	KeylogPath:       "/run/sidecar-keylog/sslkeylog.log",
	CaptureIface:     "veth0",
	CapturePath:      "/var/log/sidecar/other.pcapng",
	Retain:           true,
	MaxBytes:         2048,
	MaxAge:           12 * time.Hour,
	RetentionTick:    30 * time.Second,
	StatsInterval:    10 * time.Second,
	LogLevel:         slog.LevelWarn,
}

// C54: everySetting is only a useful fixture while each of its fields
// differs from the default: a source that dropped a setting equal to its
// default would still compare equal and pass. (The keylog-path default moved
// to the harness tmpfs path, which everySetting used to hold.)
func TestEverySetting_DiffersFromTheDefaultInEveryField(t *testing.T) {
	t.Parallel()

	got, def := reflect.ValueOf(everySetting), reflect.ValueOf(DefaultConfig())
	for i := range got.NumField() {
		name := got.Type().Field(i).Name
		assert.NotEqual(t, def.Field(i).Interface(), got.Field(i).Interface(),
			"everySetting.%s equals its default, so a source that drops it goes unnoticed", name)
	}
}

// C53 (AC 36, door 5): the default keylog path is the harness's tmpfs mount,
// never the disk-backed capture directory.
func TestDefaultConfig_KeylogPathIsTheHarnessTmpfs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log", DefaultConfig().KeylogPath)
}

// C9 (AC 5, door 3): the sidecar pins its maps under /sys/fs/bpf/netloupe-tap
// unless told otherwise, and --pin-dir advertises that default.
func TestDefaultConfig_PinDirIsNetloupeTap(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "/sys/fs/bpf/netloupe-tap", DefaultConfig().PinDir)

	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg, err := loadConfig(fs, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "/sys/fs/bpf/netloupe-tap", cfg.PinDir, "a run given no --pin-dir pins there")
	pinDir := fs.Lookup("pin-dir")
	require.NotNil(t, pinDir, "--pin-dir must be registered")
	assert.Equal(t, "/sys/fs/bpf/netloupe-tap", pinDir.DefValue)
}

// C65 (AC 46): --retain's help says what it keeps -- this run's capture,
// which carries its own TLS secrets -- and that the keylog is never kept.
func TestLoadConfig_RetainHelpSaysOnlyTheCaptureIsKept(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	_, err := loadConfig(fs, nil, nil)
	require.NoError(t, err)

	retain := fs.Lookup("retain")
	require.NotNil(t, retain, "--retain must be registered")
	assert.Contains(t, retain.Usage, "this run's capture")
	assert.Contains(t, retain.Usage, "the keylog is never kept")
}

// C67 (AC 46): --retain's help says the kept capture carries its embedded TLS
// secrets, which is how an operator learns it is plaintext-equivalent
// (AD-006).
func TestLoadConfig_RetainHelpSaysTheCaptureCarriesItsSecrets(t *testing.T) {
	t.Parallel()

	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	_, err := loadConfig(fs, nil, nil)
	require.NoError(t, err)

	retain := fs.Lookup("retain")
	require.NotNil(t, retain, "--retain must be registered")
	assert.Contains(t, retain.Usage, "with its embedded TLS secrets")
}

func TestLoadConfig_NoSourcesYieldsDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := load(t, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

func TestLoadConfig_FileSetsEverySettingInEachFormat(t *testing.T) {
	t.Parallel()

	const yamlBody = `
cgroup-path: /sys/fs/cgroup/machine.slice/pod
relay-listen: 127.0.0.1:16001
pin-dir: /sys/fs/bpf/other
keylog-socket: /run/keylog/keylog.sock
keylog-path: /run/sidecar-keylog/sslkeylog.log
capture-iface: veth0
capture-path: /var/log/sidecar/other.pcapng
retain: true
max-bytes: 2048
max-age: 12h
retention-interval: 30s
stats-interval: 10s
log-level: warn
`
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "config.yaml", body: yamlBody},
		{name: "config.yml", body: yamlBody},
		{name: "config.YAML", body: yamlBody}, // extension case is ignored
		{name: "config.toml", body: `
cgroup-path = "/sys/fs/cgroup/machine.slice/pod"
relay-listen = "127.0.0.1:16001"
pin-dir = "/sys/fs/bpf/other"
keylog-socket = "/run/keylog/keylog.sock"
keylog-path = "/run/sidecar-keylog/sslkeylog.log"
capture-iface = "veth0"
capture-path = "/var/log/sidecar/other.pcapng"
retain = true
max-bytes = 2048
max-age = "12h"
retention-interval = "30s"
stats-interval = "10s"
log-level = "warn"
`},
		{name: "config.json", body: `{
  "cgroup-path": "/sys/fs/cgroup/machine.slice/pod",
  "relay-listen": "127.0.0.1:16001",
  "pin-dir": "/sys/fs/bpf/other",
  "keylog-socket": "/run/keylog/keylog.sock",
  "keylog-path": "/run/sidecar-keylog/sslkeylog.log",
  "capture-iface": "veth0",
  "capture-path": "/var/log/sidecar/other.pcapng",
  "retain": true,
  "max-bytes": 2048,
  "max-age": "12h",
  "retention-interval": "30s",
  "stats-interval": "10s",
  "log-level": "warn"
}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, tc.name, tc.body)

			// A successful load also proves --config itself is never
			// reported as an unknown key.
			cfg, err := load(t, []string{"--config", path}, nil)

			require.NoError(t, err)
			assert.Equal(t, everySetting, cfg)
		})
	}
}

// C2 (AC 2, door 2): each of the 13 settings, set only through its variable,
// loads to everySetting's value and leaves every other setting at its
// default. The variable is NETLOUPE_TAP_SIDECAR_ plus the flag name upper-cased
// with - turned into _; values holds the names written out, so a name the rule
// does not produce has no value and fails.
func TestLoadConfig_EnvSetsEverySetting(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"NETLOUPE_TAP_SIDECAR_CGROUP_PATH":        "/sys/fs/cgroup/machine.slice/pod",
		"NETLOUPE_TAP_SIDECAR_RELAY_LISTEN":       "127.0.0.1:16001",
		"NETLOUPE_TAP_SIDECAR_PIN_DIR":            "/sys/fs/bpf/other",
		"NETLOUPE_TAP_SIDECAR_KEYLOG_SOCKET":      "/run/keylog/keylog.sock",
		"NETLOUPE_TAP_SIDECAR_KEYLOG_PATH":        "/run/sidecar-keylog/sslkeylog.log",
		"NETLOUPE_TAP_SIDECAR_CAPTURE_IFACE":      "veth0",
		"NETLOUPE_TAP_SIDECAR_CAPTURE_PATH":       "/var/log/sidecar/other.pcapng",
		"NETLOUPE_TAP_SIDECAR_RETAIN":             "true",
		"NETLOUPE_TAP_SIDECAR_MAX_BYTES":          "2048",
		"NETLOUPE_TAP_SIDECAR_MAX_AGE":            "12h",
		"NETLOUPE_TAP_SIDECAR_RETENTION_INTERVAL": "30s",
		"NETLOUPE_TAP_SIDECAR_STATS_INTERVAL":     "10s",
		"NETLOUPE_TAP_SIDECAR_LOG_LEVEL":          "warn",
	}
	settings := reflect.TypeFor[Config]()
	require.Len(t, values, settings.NumField(), "one variable per setting")
	for i := range settings.NumField() {
		flagName := settings.Field(i).Tag.Get("koanf")
		name := "NETLOUPE_TAP_SIDECAR_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value, ok := values[name]
			require.True(t, ok, "no value written out for %s, the variable of --%s", name, flagName)

			cfg, err := load(t, nil, []string{name + "=" + value})

			require.NoError(t, err)
			want := DefaultConfig()
			reflect.ValueOf(&want).Elem().Field(i).Set(reflect.ValueOf(everySetting).Field(i))
			assert.Equal(t, want, cfg)
		})
	}
}

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: 12h\ncapture-iface: veth0\nretain: true\n")

	cfg, err := load(t, []string{"--config", path}, []string{
		"NETLOUPE_TAP_SIDECAR_MAX_AGE=6h",
		"NETLOUPE_TAP_SIDECAR_CAPTURE_IFACE=eth1",
	})

	require.NoError(t, err)
	assert.Equal(t, 6*time.Hour, cfg.MaxAge)
	assert.Equal(t, "eth1", cfg.CaptureIface)
	assert.True(t, cfg.Retain, "a key only the file sets keeps the file's value")
}

func TestLoadConfig_FlagOverridesEnvAndFile(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: 12h\ncapture-iface: veth0\n")

	cfg, err := load(t,
		[]string{"--config", path, "--max-age=2h", "--capture-iface=eth2"},
		[]string{"NETLOUPE_TAP_SIDECAR_MAX_AGE=6h", "NETLOUPE_TAP_SIDECAR_CAPTURE_IFACE=eth1"},
	)

	require.NoError(t, err)
	assert.Equal(t, 2*time.Hour, cfg.MaxAge)
	assert.Equal(t, "eth2", cfg.CaptureIface)
}

func TestLoadConfig_UnsetFlagKeepsFileAndEnvValues(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: 12h\nretain: true\n")

	// --stats-interval is set so the flag layer runs with some flags given
	// and others (max-age, retain, capture-iface) left at their defaults.
	cfg, err := load(t,
		[]string{"--config", path, "--stats-interval=5s"},
		[]string{"NETLOUPE_TAP_SIDECAR_CAPTURE_IFACE=eth1"},
	)

	require.NoError(t, err)
	assert.Equal(t, 12*time.Hour, cfg.MaxAge, "unset --max-age must not restore its 24h default")
	assert.True(t, cfg.Retain, "unset --retain must not restore its false default")
	assert.Equal(t, "eth1", cfg.CaptureIface, "unset --capture-iface must not restore its eth0 default")
	assert.Equal(t, 5*time.Second, cfg.StatsInterval)
}

func TestLoadConfig_FlagEqualToDefaultStillOverrides(t *testing.T) {
	t.Parallel()
	d := DefaultConfig()
	path := writeConfig(t, "config.yaml", "retain: true\nmax-age: 12h\ncapture-path: /x.pcapng\n")

	// pod-up.sh passes --capture-path with exactly its default value, so a
	// flag given on the command line must win even when it equals its default.
	cfg, err := load(t,
		[]string{
			"--config", path,
			"--retain=false",
			"--max-age=24h",
			"--capture-iface=eth0",
			"--capture-path=" + d.CapturePath,
		},
		[]string{"NETLOUPE_TAP_SIDECAR_CAPTURE_IFACE=eth1"},
	)

	require.NoError(t, err)
	assert.False(t, cfg.Retain)
	assert.Equal(t, 24*time.Hour, cfg.MaxAge)
	assert.Equal(t, "eth0", cfg.CaptureIface)
	assert.Equal(t, d.CapturePath, cfg.CapturePath)
}

func TestLoadConfig_AcceptsExistingFlagNamesInBothForms(t *testing.T) {
	t.Parallel()

	for _, dash := range []string{"-", "--"} {
		t.Run(dash, func(t *testing.T) {
			t.Parallel()
			args := []string{
				dash + "cgroup-path=" + everySetting.CgroupPath,
				dash + "relay-listen=" + everySetting.RelayListen,
				dash + "pin-dir=" + everySetting.PinDir,
				dash + "keylog-socket=" + everySetting.KeylogSocketPath,
				dash + "keylog-path=" + everySetting.KeylogPath,
				dash + "capture-iface=" + everySetting.CaptureIface,
				dash + "capture-path=" + everySetting.CapturePath,
				dash + "retain", // bare boolean, as pod-up.sh passes it
				dash + "max-bytes=2048",
				dash + "max-age=12h",
				dash + "retention-interval=30s",
				dash + "stats-interval=10s",
				dash + "log-level=warn",
			}

			cfg, err := load(t, args, nil)

			require.NoError(t, err)
			assert.Equal(t, everySetting, cfg)
		})
	}
}

func TestLoadConfig_RejectsUnknownFileKey(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-agee: 9h\n")

	_, err := load(t, []string{"--config", path}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "max-agee")
}

func TestLoadConfig_RejectsUnknownEnvKey(t *testing.T) {
	t.Parallel()

	_, err := load(t, nil, []string{"NETLOUPE_TAP_SIDECAR_BOGUS=1"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestLoadConfig_IgnoresInterposerEnvVar(t *testing.T) {
	t.Parallel()

	cfg, err := load(t, nil, []string{"NETLOUPE_TAP_PRELOAD_SOCKET=/run/keylog/keylog.sock"})

	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

// C5 (AC 3, door 2): a variable with the prefix the sidecar read before the
// rename is refused, never skipped, whether it names a setting, names none, or
// is set beside its NETLOUPE_TAP_SIDECAR_ replacement. The error names the
// variable and that replacement.
func TestLoadConfig_RejectsOldEnvPrefix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name             string
		environ          []string
		old, replacement string
	}{
		{name: "a known setting", environ: []string{"GOEBPF_SIDECAR_MAX_BYTES=1"}, old: "GOEBPF_SIDECAR_MAX_BYTES", replacement: "NETLOUPE_TAP_SIDECAR_MAX_BYTES"},
		{name: "no setting", environ: []string{"GOEBPF_SIDECAR_BOGUS=1"}, old: "GOEBPF_SIDECAR_BOGUS", replacement: "NETLOUPE_TAP_SIDECAR_BOGUS"},
		{name: "set beside its replacement", environ: []string{"GOEBPF_SIDECAR_RETAIN=1", "NETLOUPE_TAP_SIDECAR_RETAIN=1"}, old: "GOEBPF_SIDECAR_RETAIN", replacement: "NETLOUPE_TAP_SIDECAR_RETAIN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := load(t, nil, tc.environ)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.old, "the error must name the variable")
			assert.Contains(t, err.Error(), tc.replacement, "the error must name its replacement")
		})
	}
}

// C6 (AC 3, at the boundary): the sidecar binary, started with an old-prefix
// variable set, exits 1 on the config load, before Start runs. Without the
// refusal it would reach Start, which deletes the leftover keylog at
// --keylog-path first and then fails on a --pin-dir outside bpffs with
// "app: start failed", so neither needs any privilege to be seen.
func TestApp_OldEnvPrefixExitsOneBeforeLoading(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "app")
	build := exec.Command("go", "build", "-o", bin, ".") // #nosec G204 -- bin is a test-generated temp path, not external input
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build the sidecar binary: %s", out)
	keylogPath := filepath.Join(shmDir(t), "sslkeylog.log")
	require.NoError(t, os.WriteFile(keylogPath, []byte("leftover\n"), 0o600))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, // #nosec G204 -- bin and every path are test-generated, not external input
		"--cgroup-path=/x",
		"--keylog-path="+keylogPath,
		"--pin-dir="+filepath.Join(tmp, "pin"),
		"--relay-listen=127.0.0.1:0",
		"--keylog-socket="+filepath.Join(tmp, "sock", "keylog.sock"),
		"--capture-path="+filepath.Join(tmp, "sidecar", "dump.pcapng"),
	)
	cmd.Env = []string{"GOEBPF_SIDECAR_RETAIN=1"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "the sidecar must exit with a status; stderr: %s", stderr.String())
	assert.Equal(t, 1, exitErr.ExitCode(), "stderr: %s", stderr.String())
	assert.Contains(t, stderr.String(), "app: config load failed")
	assert.Contains(t, stderr.String(), "GOEBPF_SIDECAR_RETAIN", "the error must name the variable")
	assert.Contains(t, stderr.String(), "NETLOUPE_TAP_SIDECAR_RETAIN", "the error must name its replacement")
	assert.NotContains(t, stderr.String(), "app: start failed", "the refusal must come before Start")
	assert.FileExists(t, keylogPath, "Start deletes a leftover keylog before it loads eBPF, so it must not have run")
}

func TestLoadConfig_RejectsUnsupportedExtension(t *testing.T) {
	t.Parallel()
	// The body is valid YAML and JSON, so falling back to either parser
	// would load it without error instead of rejecting the extension.
	path := writeConfig(t, "config.hcl", `{"max-age": "12h"}`)

	_, err := load(t, []string{"--config", path}, nil)

	assert.ErrorContains(t, err, `unsupported extension ".hcl"`)
}

func TestLoadConfig_RejectsUnreadableFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.yaml")

	_, err := load(t, []string{"--config", path}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
}

func TestLoadConfig_RejectsInvalidDuration(t *testing.T) {
	t.Parallel()

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		path := writeConfig(t, "config.yaml", "max-age: soon\n")

		_, err := load(t, []string{"--config", path}, nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "max-age")
	})
	t.Run("env", func(t *testing.T) {
		t.Parallel()

		_, err := load(t, nil, []string{"NETLOUPE_TAP_SIDECAR_STATS_INTERVAL=soon"})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "stats-interval")
	})
}

func TestLoadConfig_RejectsValuesThatDoNotParseAsTheirType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		file    string // YAML body; empty means no config file
		environ []string
		key     string
	}{
		{name: "empty integer env var", environ: []string{"NETLOUPE_TAP_SIDECAR_MAX_BYTES="}, key: "max-bytes"},
		{name: "non-numeric integer env var", environ: []string{"NETLOUPE_TAP_SIDECAR_MAX_BYTES=lots"}, key: "max-bytes"},
		{name: "empty integer in file", file: `max-bytes: ""`, key: "max-bytes"},
		{name: "fractional integer in file", file: "max-bytes: 1.9", key: "max-bytes"},
		{name: "non-boolean env var", environ: []string{"NETLOUPE_TAP_SIDECAR_RETAIN=maybe"}, key: "retain"},
		{name: "empty boolean env var", environ: []string{"NETLOUPE_TAP_SIDECAR_RETAIN="}, key: "retain"},
		{name: "duration without a unit in file", file: "max-age: 3600", key: "max-age"},
		{name: "integer beyond int64 in file", file: "max-bytes: 1e20", key: "max-bytes"},
		{name: "integer below int64 in file", file: "max-bytes: -1e20", key: "max-bytes"},
		{name: "float at 2^63 in file", file: "max-bytes: 9.223372036854775808e18", key: "max-bytes"},
		{name: "integer literal at 2^63 in file", file: "max-bytes: 9223372036854775808", key: "max-bytes"},
		{name: "integer literal at 2^64-1 in file", file: "max-bytes: 18446744073709551615", key: "max-bytes"},
		{name: "boolean for an integer in file", file: "max-bytes: true", key: "max-bytes"},
		{name: "boolean for a duration in file", file: "max-age: true", key: "max-age"},
		{name: "number for a boolean in file", file: "retain: 2", key: "retain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var args []string
			if tc.file != "" {
				args = []string{"--config", writeConfig(t, "config.yaml", tc.file+"\n")}
			}

			_, err := load(t, args, tc.environ)

			assert.ErrorContains(t, err, tc.key)
		})
	}
}

func TestLoadConfig_RejectsSettingsWithoutValue(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		file string
		body string
		key  string
	}{
		{file: "config.yaml", body: "max-bytes:\n", key: "max-bytes"},
		{file: "config.yaml", body: "max-age:\n", key: "max-age"},
		{file: "config.yaml", body: "retain:\n", key: "retain"},
		{file: "config.json", body: `{"max-bytes": null}`, key: "max-bytes"},
	} {
		t.Run(tc.file+"/"+tc.key, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, tc.file, tc.body)

			_, err := load(t, []string{"--config", path}, nil)

			assert.ErrorContains(t, err, tc.key)
		})
	}
}

func TestLoadConfig_AcceptsInt64Minimum(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-bytes: -9.223372036854775808e18\n")

	cfg, err := load(t, []string{"--config", path}, nil)

	require.NoError(t, err)
	assert.Equal(t, int64(math.MinInt64), cfg.MaxBytes)
}

func TestLoadConfig_HigherLayerReplacesInvalidFileValue(t *testing.T) {
	t.Parallel()

	t.Run("flag over a key with no value", func(t *testing.T) {
		t.Parallel()
		path := writeConfig(t, "config.yaml", "max-bytes:\n")

		cfg, err := load(t, []string{"--config", path, "--max-bytes=5"}, nil)

		require.NoError(t, err)
		assert.Equal(t, int64(5), cfg.MaxBytes)
	})
	t.Run("env over an invalid duration", func(t *testing.T) {
		t.Parallel()
		path := writeConfig(t, "config.yaml", "max-age: soon\n")

		cfg, err := load(t, []string{"--config", path}, []string{"NETLOUPE_TAP_SIDECAR_MAX_AGE=1h"})

		require.NoError(t, err)
		assert.Equal(t, time.Hour, cfg.MaxAge)
	})
}

func TestLoadConfig_AcceptsZeroDuration(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: 0\n")

	cfg, err := load(t, []string{"--config", path}, nil)

	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), cfg.MaxAge)
}

func TestLoadConfig_RejectsMalformedFile(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: [12h\n")

	_, err := load(t, []string{"--config", path}, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
}

// A level is a slog level name in every source, in any case and optionally
// offset; the flag rejects an unknown name at parse time.
func TestLoadConfig_LogLevelByName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		args    []string
		environ []string
		want    slog.Level
	}{
		{name: "file", args: []string{"--config", "FILE"}, want: slog.LevelDebug},
		{name: "env", environ: []string{"NETLOUPE_TAP_SIDECAR_LOG_LEVEL=WARN+2"}, want: slog.LevelWarn + 2},
		{name: "flag", args: []string{"--log-level=error"}, want: slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if len(tc.args) == 2 && tc.args[1] == "FILE" {
				tc.args = []string{"--config", writeConfig(t, "config.yaml", "log-level: debug\n")}
			}

			cfg, err := load(t, tc.args, tc.environ)

			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.LogLevel)
		})
	}

	t.Run("unknown flag value", func(t *testing.T) {
		t.Parallel()

		_, err := load(t, []string{"--log-level=loud"}, nil)

		assert.ErrorContains(t, err, "log-level")
	})
}

// A level must be a slog level name: an unknown or empty name, or a number
// or boolean in a file, is an error rather than a silently decoded level.
func TestLoadConfig_RejectsLogLevelThatIsNotAName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		file    string // YAML body; empty means no config file
		environ []string
	}{
		{name: "unknown name env var", environ: []string{"NETLOUPE_TAP_SIDECAR_LOG_LEVEL=loud"}},
		{name: "empty env var", environ: []string{"NETLOUPE_TAP_SIDECAR_LOG_LEVEL="}},
		{name: "unknown name in file", file: "log-level: loud"},
		{name: "number in file", file: "log-level: 4"},
		{name: "fractional number in file", file: "log-level: 1.9"},
		{name: "boolean in file", file: "log-level: true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var args []string
			if tc.file != "" {
				args = []string{"--config", writeConfig(t, "config.yaml", tc.file+"\n")}
			}

			_, err := load(t, args, tc.environ)

			assert.ErrorContains(t, err, "log-level")
		})
	}
}
