package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
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
// It is deliberately not the bare NETLOUPE_TAP_ prefix: the LD_PRELOAD
// interposer owns NETLOUPE_TAP_PRELOAD_SOCKET, which is not a sidecar setting
// and would otherwise be rejected as an unknown key.
const envPrefix = "NETLOUPE_TAP_SIDECAR_"

// oldEnvPrefix is the prefix the sidecar read its settings from before the
// project was renamed netloupe-tap. koanf's env provider would skip such a
// variable silently, so a forgotten GOEBPF_SIDECAR_MAX_BYTES would lift the
// bound on key-bearing captures and GOEBPF_SIDECAR_RETAIN=1 would let teardown
// delete a capture the operator meant to keep; loadConfig refuses it instead.
const oldEnvPrefix = "GOEBPF_SIDECAR_"

// configFlag names the flag that points at the optional config file. It
// selects a source rather than being a setting, so it never enters the
// merged configuration.
const configFlag = "config"

// loadConfig registers the sidecar's flags on fs, parses args, and merges
// every configuration source into a Config. Precedence, lowest first:
// DefaultConfig(), the file named by --config, NETLOUPE_TAP_SIDECAR_*
// variables in environ, and the flags actually set in args. A setting's key is
// its flag name in every source (NETLOUPE_TAP_SIDECAR_MAX_AGE is max-age), and
// a key that names no setting, or a value that does not parse as its setting's
// type, is an error rather than being ignored or coerced. So is any variable in
// environ that still carries oldEnvPrefix, whatever it names.
func loadConfig(fs *flag.FlagSet, args, environ []string) (Config, error) {
	d := DefaultConfig()
	fs.String("cgroup-path", d.CgroupPath, "pod common-parent cgroup v2 path to attach connect4/sockops (required)")
	fs.String("relay-listen", d.RelayListen, "address the pass-through relay listens on")
	fs.String("pin-dir", d.PinDir, "bpffs directory for the connect4/sockops pinned maps")
	fs.String("keylog-socket", d.KeylogSocketPath, "unix domain socket the LD_PRELOAD keylog interposer connects to")
	fs.String("keylog-path", d.KeylogPath, "path to the NSS keylog file; its directory must be on tmpfs, or the sidecar refuses to start")
	fs.String("capture-iface", d.CaptureIface, "interface to capture: every frame, both directions, unfiltered (the relay's outbound leg and all other pod traffic)")
	fs.String("capture-path", d.CapturePath, "template for each run's DSB-embedded pcapng capture: a run writes <stem>-<unix start second><ext> in its directory, never overwriting a file")
	fs.Bool("retain", d.Retain, "keep this run's capture, with its embedded TLS secrets, on teardown instead of deleting it; the keylog is never kept")
	fs.Int64("max-bytes", d.MaxBytes, "size limit in bytes on the captures in the capture directory, this run's included: reaching it stops capture and keeps the file (0 disables)")
	fs.Duration("max-age", d.MaxAge, "age past which finished captures are deleted, never the live one (0 disables)")
	fs.Duration("retention-interval", d.RetentionTick, "how often to enforce retention while running (0 disables)")
	fs.Duration("stats-interval", d.StatsInterval, "how often to log the cumulative counters as a \"stats\" line, plus once at shutdown (0 disables)")
	fs.String("metrics-endpoint", d.MetricsEndpoint, "OTLP/HTTP URL to push the relay's metrics to, such as http://collector:4318 (an empty path means /v1/metrics), without credentials: those go in OTEL_EXPORTER_OTLP_HEADERS; empty disables metrics")
	fs.Duration("metrics-interval", d.MetricsInterval, "how often metrics are pushed to --metrics-endpoint")
	fs.Int64("metrics-cardinality-limit", d.MetricsCardinalityLimit, "most series one metric carries per push; the rest are summed into one overflow series (0 disables the limit)")
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
	if err := refuseOldEnvPrefix(environ); err != nil {
		return Config{}, fmt.Errorf("config env: %w", err)
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
	if err := validateMetrics(cfg); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if cfg.MetricsEndpoint != "" {
		if err := errors.Join(validateOTLPHeaders(environ), refuseHeaderDump(environ)); err != nil {
			return Config{}, fmt.Errorf("config env: %w", err)
		}
	}
	return cfg, nil
}

// otlpHeaderVars are the variables the OTLP/HTTP metrics exporter reads
// request headers from, which is how a collector credential is set (AD-033).
var otlpHeaderVars = []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_HEADERS"}

// validateOTLPHeaders refuses a header variable the exporter could not parse
// in full. The exporter would skip the bad header, so a credential would be
// silently dropped, and it would log the header it skipped, value included.
// The errors name the variable and the header's position, never its text: a
// header written "Authorization: Bearer x" has the secret in its name.
func validateOTLPHeaders(environ []string) error {
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		// The exporter trims the variable and reads a blank one as unset.
		if !slices.Contains(otlpHeaderVars, name) || strings.TrimSpace(value) == "" {
			continue
		}
		for i, header := range strings.Split(value, ",") {
			if _, problem := parseOTLPHeader(header); problem != "" {
				return fmt.Errorf("%s: header %d %s", name, i+1, problem)
			}
		}
	}
	return nil
}

// parseOTLPHeader parses one name=value element of a header variable as the
// exporter does and returns the value it would send. problem is empty for a
// header the exporter sends; otherwise it says, without quoting the element,
// why the exporter would skip it.
func parseOTLPHeader(header string) (value, problem string) {
	name, raw, found := strings.Cut(header, "=")
	value, err := url.PathUnescape(raw)
	switch {
	case !found:
		return "", "has no '=' (write name=value)"
	case !isHeaderName(strings.TrimSpace(name)):
		return "", "has an invalid name"
	case err != nil:
		return "", "has a value with an invalid percent escape"
	}
	return strings.TrimSpace(value), ""
}

// minMaskedLen is the shortest header value, or part of one, that the log
// masks. A shorter string is left alone: masking it would blank ordinary
// words and numbers out of every line.
const minMaskedLen = 8

// otlpHeaderSecrets returns what the log masks of the request headers the
// exporter is given through otlpHeaderVars: each header's value and each
// whitespace-separated part of it, so the token of "Bearer <token>" is
// covered on its own, both as sent and percent-encoded, as a redirect would
// carry it in a URL. Strings shorter than minMaskedLen are left out. So is a
// header the exporter would skip: it is never sent, so no one can send it
// back.
func otlpHeaderSecrets(environ []string) []string {
	var secrets []string
	add := func(part string) {
		if len(part) < minMaskedLen {
			return
		}
		for _, form := range []string{part, url.QueryEscape(part), url.PathEscape(part)} {
			if !slices.Contains(secrets, form) {
				secrets = append(secrets, form)
			}
		}
	}
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !slices.Contains(otlpHeaderVars, name) {
			continue
		}
		for _, header := range strings.Split(value, ",") {
			sent, problem := parseOTLPHeader(header)
			if problem != "" {
				continue
			}
			add(sent)
			for _, part := range strings.Fields(sent) {
				add(part)
			}
		}
	}
	return secrets
}

// refuseHeaderDump refuses to run with Go's HTTP/2 debugging on while a
// header variable is set. GODEBUG=http2debug=1 or =2 makes net/http print
// every request header with its value on each push, straight to stderr, past
// the sidecar's logger and its masking. The error names the two variables,
// never a value.
func refuseHeaderDump(environ []string) error {
	var debug bool
	var headerVar string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		switch {
		case name == "GODEBUG":
			// The test net/http applies to GODEBUG, verbatim.
			debug = debug || strings.Contains(value, "http2debug=1") || strings.Contains(value, "http2debug=2")
		case slices.Contains(otlpHeaderVars, name) && strings.TrimSpace(value) != "":
			headerVar = name
		}
	}
	if debug && headerVar != "" {
		return fmt.Errorf("GODEBUG sets http2debug, which prints every request header with its value: unset it, or unset %s", headerVar)
	}
	return nil
}

// isHeaderName reports whether s is an HTTP header name: a non-empty token
// (RFC 9110), the rule the exporter applies.
func isHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		letterOrDigit := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !letterOrDigit && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	return true
}

// validateMetrics refuses metrics settings the exporter would otherwise
// replace with its own defaults or run with silently: an endpoint that is not
// an http(s) URL with a host, a push interval that is not positive, and a
// negative cardinality limit.
func validateMetrics(cfg Config) error {
	if cfg.MetricsEndpoint != "" {
		if _, err := metricsURL(cfg.MetricsEndpoint); err != nil {
			return err
		}
	}
	if cfg.MetricsInterval <= 0 {
		return fmt.Errorf("metrics-interval %s must be above 0", cfg.MetricsInterval)
	}
	if cfg.MetricsCardinalityLimit < 0 {
		return fmt.Errorf("metrics-cardinality-limit %d must not be negative (0 disables the limit)", cfg.MetricsCardinalityLimit)
	}
	return nil
}

// metricsURL parses a metrics-endpoint value into the URL metrics are pushed
// to: an http or https URL with a host, whose empty path becomes the OTLP
// default /v1/metrics. Credentials, a query and a fragment are refused: the
// exporter sends only the scheme, host and path, so a secret in any of them
// would be dropped, and logged with the endpoint. Its errors never repeat the
// value.
func metricsURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("metrics-endpoint is not a URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("metrics-endpoint must be an http:// or https:// URL")
	}
	if u.Hostname() == "" {
		return nil, errors.New("metrics-endpoint names no host")
	}
	if u.User != nil {
		return nil, errors.New("metrics-endpoint must not carry credentials; set them in OTEL_EXPORTER_OTLP_HEADERS")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("metrics-endpoint must not carry a query or fragment, which the exporter does not send; set a credential in OTEL_EXPORTER_OTLP_HEADERS")
	}
	if u.Path == "" {
		u.Path = "/v1/metrics"
	}
	return u, nil
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
// NETLOUPE_TAP_SIDECAR_MAX_AGE becomes max-age.
func envKey(name, value string) (string, any) {
	return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(name, envPrefix)), "_", "-"), value
}

// refuseOldEnvPrefix returns an error naming every variable in environ that
// carries oldEnvPrefix, each with the envPrefix variable that replaces it, or
// nil when there is none. It names variables only, never their values.
func refuseOldEnvPrefix(environ []string) error {
	var errs []error
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if rest, ok := strings.CutPrefix(name, oldEnvPrefix); ok {
			errs = append(errs, fmt.Errorf("%s is no longer read; set %s%s instead", name, envPrefix, rest))
		}
	}
	return errors.Join(errs...)
}
