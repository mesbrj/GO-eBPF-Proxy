package main

import (
	"flag"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
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
	KeylogPath:       "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log",
	CaptureIface:     "veth0",
	CapturePath:      "/var/log/sidecar/other.pcapng",
	Retain:           true,
	MaxBytes:         2048,
	MaxAge:           12 * time.Hour,
	RetentionTick:    30 * time.Second,
	StatsInterval:    10 * time.Second,
	LogLevel:         slog.LevelWarn,
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
keylog-path: /var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log
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
keylog-path = "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log"
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
  "keylog-path": "/var/log/sidecar-keylog-tmpfs/keylog/sslkeylog.log",
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

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "config.yaml", "max-age: 12h\ncapture-iface: veth0\nretain: true\n")

	cfg, err := load(t, []string{"--config", path}, []string{
		"GOEBPF_SIDECAR_MAX_AGE=6h",
		"GOEBPF_SIDECAR_CAPTURE_IFACE=eth1",
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
		[]string{"GOEBPF_SIDECAR_MAX_AGE=6h", "GOEBPF_SIDECAR_CAPTURE_IFACE=eth1"},
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
		[]string{"GOEBPF_SIDECAR_CAPTURE_IFACE=eth1"},
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
		[]string{"GOEBPF_SIDECAR_CAPTURE_IFACE=eth1"},
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

	_, err := load(t, nil, []string{"GOEBPF_SIDECAR_BOGUS=1"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestLoadConfig_IgnoresInterposerEnvVar(t *testing.T) {
	t.Parallel()

	cfg, err := load(t, nil, []string{"GOEBPF_PRELOAD_SOCKET=/run/keylog/keylog.sock"})

	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
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

		_, err := load(t, nil, []string{"GOEBPF_SIDECAR_STATS_INTERVAL=soon"})

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
		{name: "empty integer env var", environ: []string{"GOEBPF_SIDECAR_MAX_BYTES="}, key: "max-bytes"},
		{name: "non-numeric integer env var", environ: []string{"GOEBPF_SIDECAR_MAX_BYTES=lots"}, key: "max-bytes"},
		{name: "empty integer in file", file: `max-bytes: ""`, key: "max-bytes"},
		{name: "fractional integer in file", file: "max-bytes: 1.9", key: "max-bytes"},
		{name: "non-boolean env var", environ: []string{"GOEBPF_SIDECAR_RETAIN=maybe"}, key: "retain"},
		{name: "empty boolean env var", environ: []string{"GOEBPF_SIDECAR_RETAIN="}, key: "retain"},
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

		cfg, err := load(t, []string{"--config", path}, []string{"GOEBPF_SIDECAR_MAX_AGE=1h"})

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
		{name: "env", environ: []string{"GOEBPF_SIDECAR_LOG_LEVEL=WARN+2"}, want: slog.LevelWarn + 2},
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
		{name: "unknown name env var", environ: []string{"GOEBPF_SIDECAR_LOG_LEVEL=loud"}},
		{name: "empty env var", environ: []string{"GOEBPF_SIDECAR_LOG_LEVEL="}},
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
