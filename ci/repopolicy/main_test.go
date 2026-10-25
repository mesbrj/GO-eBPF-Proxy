// Package repopolicy pins the repository's CI and review policy (feature
// 08-ci-pipeline): the workflows, Dependabot, the main ruleset and CODEOWNERS
// under .github, the Makefile's pinned tool targets, .github/scripts/repo-policy.sh
// and the vendored the-judge scripts. It holds tests only. go test ./... skips
// dot-directories, so the tests live here and read those files from the
// repository root.
package repopolicy

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMain doubles as the fake gh: newFakeGH puts a symlink named gh to this
// test binary first on PATH, and a process started under that name answers
// from canned responses instead of running the tests.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "gh" {
		os.Exit(runFakeGH(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	return root
}

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), filepath.FromSlash(rel))
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(repoPath(t, rel)) // #nosec G304 -- a repository file named by the test
	require.NoError(t, err)
	return b
}

// cleanEnv is the test process environment without the variables that would
// let the caller's shell change what a script under test does.
func cleanEnv(extra ...string) []string {
	drop := map[string]bool{
		"GH_TOKEN": true, "GITHUB_TOKEN": true, "GH_REPO": true,
		"JUDGE_BOT_LOGIN": true, "REPO": true, fakeGHDirEnv: true,
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// result is what a finished process printed and exited with.
type result struct {
	stdout, stderr string
	code           int
}

func (r result) output() string { return r.stdout + r.stderr }

func run(t *testing.T, cmd *exec.Cmd) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "start %v: %v", cmd.Args, err)
		code = exitErr.ExitCode()
	}
	return result{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// runStep runs a workflow step's run: script the way GitHub runs it under
// defaults.run.shell: bash.
func runStep(t *testing.T, script string, env []string) result {
	t.Helper()
	return runStepIn(t, "", script, env)
}

// runStepIn is runStep with dir as the working directory.
func runStepIn(t *testing.T, dir, script string, env []string) result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "step.sh")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))
	cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", path) // #nosec G204 -- a temp script written by the test
	cmd.Dir = dir
	cmd.Env = env
	return run(t, cmd)
}

// nonEmptyLines splits s into lines, dropping blank ones.
func nonEmptyLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
