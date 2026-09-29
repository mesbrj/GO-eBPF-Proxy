package main

import (
	"flag"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/basicflag"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// envPrefix marks the environment variables the sidecar reads settings from.
// It is deliberately not the bare GOEBPF_ prefix: the LD_PRELOAD interposer
// owns GOEBPF_PRELOAD_SOCKET, which is not a sidecar setting and would
// otherwise be rejected as an unknown key.
const envPrefix = "GOEBPF_SIDECAR_"

// configFlag names the flag that points at the optional config file. It
// selects a source rather than being a setting, so it never enters the
// merged configuration.
const configFlag = "config"

// loadConfig registers the sidecar's flags on fs, parses args, and merges
// every configuration source into a Config. Precedence, lowest first:
// DefaultConfig(), the file named by --config, GOEBPF_SIDECAR_* variables in
// environ, and the flags actually set in args. A setting's key is its flag
// name in every source (GOEBPF_SIDECAR_MAX_AGE is max-age), and a key that
// names no setting, or a value that does not parse as its setting's type, is
// an error rather than being ignored or coerced.
func loadConfig(fs *flag.FlagSet, args, environ []string) (Config, error) {
	d := DefaultConfig()
	fs.String("cgroup-path", d.CgroupPath, "pod common-parent cgroup v2 path to attach connect4/sockops (required)")
	fs.String("relay-listen", d.RelayListen, "address the pass-through relay listens on")
	fs.String("pin-dir", d.PinDir, "bpffs directory for the connect4/sockops pinned maps")
	fs.String("keylog-socket", d.KeylogSocketPath, "unix domain socket the LD_PRELOAD keylog interposer connects to")
	fs.String("keylog-path", d.KeylogPath, "path to the NSS keylog file (should be on tmpfs)")
	fs.String("capture-iface", d.CaptureIface, "interface to capture the outbound leg from")
	fs.String("capture-path", d.CapturePath, "path to the DSB-embedded pcapng capture file")
	fs.Bool("retain", d.Retain, "keep capture/keylog artifacts on teardown instead of wiping them")
	fs.Int64("max-bytes", d.MaxBytes, "capture directory size cap in bytes (0 disables)")
	fs.Duration("max-age", d.MaxAge, "capture artifact age cap (0 disables)")
	fs.Duration("retention-interval", d.RetentionTick, "how often to enforce retention while running (0 disables)")
	fs.Duration("stats-interval", d.StatsInterval, "how often to log the cumulative counters as a \"stats\" line, plus once at shutdown (0 disables)")
	fs.TextVar(new(slog.Level), "log-level", d.LogLevel, "minimum level logged: debug, info, warn or error, optionally offset like warn+2")
	path := fs.String(configFlag, "", "optional config file (.yaml, .yml, .toml or .json); "+envPrefix+"* env vars and flags override it")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	k := koanf.New(".")
	if *path != "" {
		p, err := parserFor(*path)
		if err != nil {
			return Config{}, err
		}
		if err := k.Load(file.Provider(*path), p); err != nil {
			return Config{}, fmt.Errorf("config file %s: %w", *path, err)
		}
	}
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix:        envPrefix,
		TransformFunc: envKey,
		EnvironFunc:   func() []string { return environ },
	}), nil); err != nil {
		return Config{}, fmt.Errorf("config env: %w", err)
	}
	// With k as the key map, a flag left unset only fills a key that neither
	// the file nor the environment supplied, so its default (DefaultConfig())
	// never overrides them.
	skipConfigFlag := func(key, value string) (string, any) {
		if key == configFlag {
			return "", nil
		}
		return key, value
	}
	if err := k.Load(basicflag.ProviderWithValue(fs, ".", skipConfigFlag, k), nil); err != nil {
		return Config{}, fmt.Errorf("config flags: %w", err)
	}

	// A key with no value (YAML "max-bytes:", JSON null) skips the decode
	// hooks and keeps the flag default out, so it would silently decode to
	// the zero value, which disables a cap.
	for _, key := range k.Keys() {
		if k.Get(key) == nil {
			return Config{}, fmt.Errorf("config: %s has no value", key)
		}
	}

	var cfg Config
	// A custom DecoderConfig replaces koanf's default one, so the duration
	// hook koanf would otherwise install is restated here. Weak typing stays
	// off so a value of the wrong type (a boolean for max-bytes, a number for
	// retain) is an error instead of being coerced; env and flag values, which
	// always arrive as strings, are parsed strictly by the string hooks, and
	// log-level by slog.Level's own UnmarshalText.
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToInt64HookFunc(),
			mapstructure.StringToBoolHookFunc(),
			mapstructure.TextUnmarshallerHookFunc(),
			strictNumbers,
			levelByName,
		),
		ErrorUnused: true,
		Result:      &cfg,
	}})
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

var durationType = reflect.TypeFor[time.Duration]()

// strictNumbers rejects the number conversions mapstructure would otherwise
// make silently: a bare non-zero number as a duration (YAML "max-age: 3600"
// would mean 3.6µs, not an hour), a float that is fractional or outside the
// int64 range as an integer (it would be truncated or wrap negative), and an
// unsigned integer above the int64 range (YAML decodes literals of 2^63 and up
// as uint64, which would also wrap negative). The bare number 0 stays a valid
// "disabled" duration.
func strictNumbers(from, to reflect.Type, data any) (any, error) {
	if from == durationType {
		return data, nil
	}
	v := reflect.ValueOf(data)
	isFloat := from.Kind() == reflect.Float32 || from.Kind() == reflect.Float64
	isNumber := isFloat || v.CanInt() || v.CanUint()
	switch {
	case to == durationType && isNumber && !v.IsZero():
		return nil, fmt.Errorf("duration %v has no unit (write it like \"12h\")", data)
	case to.Kind() == reflect.Int64 && isFloat && !isInt64(v.Float()):
		return nil, fmt.Errorf("%v is not a whole number in the int64 range", data)
	case to.Kind() == reflect.Int64 && v.CanUint() && v.Uint() > math.MaxInt64:
		return nil, fmt.Errorf("%v is outside the int64 range", data)
	}
	return data, nil
}

// isInt64 reports whether f is a whole number that int64 can hold.
func isInt64(f float64) bool {
	return f == math.Trunc(f) && f >= -(1<<63) && f < 1<<63
}

var (
	levelType    = reflect.TypeFor[slog.Level]()
	levelPtrType = reflect.TypeFor[*slog.Level]()
)

// levelByName rejects a log level that is not a name. A name has already
// been decoded by now: TextUnmarshallerHookFunc runs slog.Level's
// UnmarshalText, which errors on an unknown one, and hands on a *slog.Level.
// Any other value is a number or boolean from a config file, which
// mapstructure would otherwise decode silently: YAML "log-level: 1.9" would
// become level 1.
func levelByName(from, to reflect.Type, data any) (any, error) {
	if to == levelType && from != levelType && from != levelPtrType {
		return nil, fmt.Errorf("log level %v is not a name (write it like \"warn\")", data)
	}
	return data, nil
}

// parserFor picks the config file's parser from its extension.
func parserFor(path string) (koanf.Parser, error) {
	switch ext := filepath.Ext(path); strings.ToLower(ext) {
	case ".yaml", ".yml":
		return yaml.Parser(), nil
	case ".toml":
		return toml.Parser(), nil
	case ".json":
		return json.Parser(), nil
	default:
		return nil, fmt.Errorf("config file %s: unsupported extension %q (want .yaml, .yml, .toml or .json)", path, ext)
	}
}

// envKey maps an environment variable to its setting key:
// GOEBPF_SIDECAR_MAX_AGE becomes max-age.
func envKey(name, value string) (string, any) {
	return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(name, envPrefix)), "_", "-"), value
}
