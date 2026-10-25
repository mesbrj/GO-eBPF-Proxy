package repopolicy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeGHDirEnv names the directory holding the fake gh's canned responses
// (responses.json) and its call log (calls.jsonl).
const fakeGHDirEnv = "FAKE_GH_DIR"

// ghResponse is what the fake gh prints and exits with for one call.
type ghResponse struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Exit   int    `json:"exit"`
}

// ghCall is one recorded invocation of the fake gh. Key is "METHOD path" for
// gh api (query string dropped) and the joined arguments otherwise. Input is
// the content of the file passed with --input, read at call time.
type ghCall struct {
	Args  []string `json:"args"`
	Key   string   `json:"key"`
	Input string   `json:"input,omitempty"`
}

// fakeGH stands in for GitHub's CLI. A response key matches a call whose key
// equals it, or, failing that, starts with it followed by a space; the longest
// such key wins. An unanswered gh api write succeeds with "{}"; any other
// unanswered call fails, so a read the test did not expect cannot pass. A call
// that passes --jq (or -q) gets its canned stdout filtered through jq -r, as gh
// prints only the matching values, strings unquoted (gh help formatting): a
// response holds what GitHub returns, and the script's own filter runs on it.
type fakeGH struct {
	t   *testing.T
	dir string
}

func newFakeGH(t *testing.T, responses map[string]ghResponse) *fakeGH {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	require.NoError(t, os.Mkdir(bin, 0o700))
	self, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, os.Symlink(self, filepath.Join(bin, "gh")))
	f := &fakeGH{t: t, dir: dir}
	f.respond(responses)
	return f
}

// respond replaces the canned responses and clears the call log.
func (f *fakeGH) respond(responses map[string]ghResponse) {
	b, err := json.Marshal(responses)
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, "responses.json"), b, 0o600))
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, "calls.jsonl"), nil, 0o600))
}

// env is cleanEnv with this fake first on PATH. Under -race the fake would
// otherwise sleep the race runtime's default 1 s before every clean exit.
func (f *fakeGH) env(extra ...string) []string {
	var env []string
	for _, kv := range cleanEnv() {
		if !strings.HasPrefix(kv, "PATH=") && !strings.HasPrefix(kv, "GORACE=") {
			env = append(env, kv)
		}
	}
	env = append(env,
		"PATH="+filepath.Join(f.dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		fakeGHDirEnv+"="+f.dir,
		"GORACE="+strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0"),
	)
	return append(env, extra...)
}

// calls returns every call recorded since the last respond.
func (f *fakeGH) calls() []ghCall {
	file, err := os.Open(filepath.Join(f.dir, "calls.jsonl"))
	require.NoError(f.t, err)
	defer func() { _ = file.Close() }()
	var calls []ghCall
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var c ghCall
		require.NoError(f.t, json.Unmarshal(sc.Bytes(), &c))
		calls = append(calls, c)
	}
	require.NoError(f.t, sc.Err())
	return calls
}

func callKeys(calls []ghCall) []string {
	keys := make([]string, len(calls))
	for i, c := range calls {
		keys[i] = c.Key
	}
	return keys
}

// ghAPIValueFlags are the gh api flags that take a value; bodyFlags among them
// make gh default the method to POST.
var (
	ghAPIValueFlags = map[string]bool{
		"-X": true, "--method": true, "-f": true, "--raw-field": true, "-F": true, "--field": true,
		"-H": true, "--header": true, "--input": true, "-q": true, "--jq": true, "-t": true,
		"--template": true, "--hostname": true, "--cache": true, "-p": true, "--preview": true,
	}
	ghAPIBodyFlags = map[string]bool{"-f": true, "--raw-field": true, "-F": true, "--field": true, "--input": true}
)

func ghKey(args []string) string {
	if len(args) == 0 || args[0] != "api" {
		return strings.Join(args, " ")
	}
	method, path, body := "", "", false
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-X" || a == "--method":
			if i++; i < len(args) {
				method = strings.ToUpper(args[i])
			}
		case ghAPIValueFlags[a]:
			body = body || ghAPIBodyFlags[a]
			i++
		case strings.HasPrefix(a, "-"):
		case path == "":
			path = a
		}
	}
	if method == "" {
		method = "GET"
		if body {
			method = "POST"
		}
	}
	path, _, _ = strings.Cut(path, "?")
	return method + " " + path
}

// apiFields returns the key=value pairs a gh api call sends with -f/-F.
func apiFields(args []string) map[string]string {
	fields := map[string]string{}
	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "-f", "--raw-field", "-F", "--field":
			k, v, _ := strings.Cut(args[i+1], "=")
			fields[k] = v
			i++
		}
	}
	return fields
}

func flagValue(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func lookupResponse(responses map[string]ghResponse, key string) (ghResponse, bool) {
	if r, ok := responses[key]; ok {
		return r, true
	}
	best, found := "", false
	for k := range responses {
		if strings.HasPrefix(key, k+" ") && len(k) > len(best) {
			best, found = k, true
		}
	}
	return responses[best], found
}

// runFakeGH is the fake gh's main.
func runFakeGH(args []string) int {
	dir := os.Getenv(fakeGHDirEnv)
	call := ghCall{Args: args, Key: ghKey(args)}
	if in := flagValue(args, "--input"); in != "" {
		b, err := os.ReadFile(in) // #nosec G304 G703 -- the file the script under test passed with --input
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake gh:", err)
			return 1
		}
		call.Input = string(b)
	}
	if err := appendCall(dir, call); err != nil {
		fmt.Fprintln(os.Stderr, "fake gh:", err)
		return 1
	}
	b, err := os.ReadFile(filepath.Join(dir, "responses.json")) // #nosec G304 G703 -- the fake's own state directory
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake gh:", err)
		return 1
	}
	var responses map[string]ghResponse
	if err := json.Unmarshal(b, &responses); err != nil {
		fmt.Fprintln(os.Stderr, "fake gh:", err)
		return 1
	}
	resp, ok := lookupResponse(responses, call.Key)
	if !ok {
		if args[0] != "api" || strings.HasPrefix(call.Key, "GET ") {
			fmt.Fprintf(os.Stderr, "fake gh: no response for %q\n", call.Key)
			return 1
		}
		resp = ghResponse{Stdout: "{}"}
	}
	stdout := resp.Stdout
	if filter := jqFilter(args); filter != "" && resp.Exit == 0 {
		out, err := applyJQ(filter, stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake gh:", err)
			return 1
		}
		stdout = out
	}
	_, _ = fmt.Fprint(os.Stdout, stdout)
	_, _ = fmt.Fprint(os.Stderr, resp.Stderr)
	return resp.Exit
}

// jqFilter returns the expression a gh call passes with --jq or -q.
func jqFilter(args []string) string {
	if f := flagValue(args, "--jq"); f != "" {
		return f
	}
	return flagValue(args, "-q")
}

func applyJQ(filter, input string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("jq", "-r", filter) // #nosec G204 G702 -- the filter the script under test passed to gh
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("jq -r %q: %w: %s", filter, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func appendCall(dir string, call ghCall) error {
	line, err := json.Marshal(call)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "calls.jsonl"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 G703 -- the fake's own state directory
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
