package repopolicy

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ciGateJobs are the jobs ci-ok folds into the one required check (AC 1).
var ciGateJobs = []string{"workflow-lint", "lint", "build", "test", "test-integration", "generate-drift", "preload", "govulncheck"}

func runLine(cmd string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(cmd) + `\s*$`)
}

// C4 (AC 1)
func TestCIWorkflow_RunsEveryGateOnPullRequestAndPushToMain(t *testing.T) {
	ci := repoWorkflow(t, "ci.yml")

	on := triggers(ci.wf)
	for _, ev := range []string{"pull_request", "push"} {
		require.Contains(t, on, ev)
		cfg, ok := on[ev].(map[string]any)
		require.True(t, ok, "%s has no configuration", ev)
		assert.Equal(t, []any{"main"}, cfg["branches"], "%s branches", ev)
	}

	assert.ElementsMatch(t, append(append([]string{}, ciGateJobs...), "ci-ok"), ci.jobNames())
	assert.Equal(t, []any{"static", "dynamic"}, ci.job(t, "build").Strategy.Matrix["link_mode"])
}

// C6 (AC 2, door 1)
func TestCIWorkflow_CiOkNeedsEveryOtherJobAndAlwaysRuns(t *testing.T) {
	ci := repoWorkflow(t, "ci.yml")
	ok := ci.job(t, "ci-ok")

	var others []string
	for _, name := range ci.jobNames() {
		if name != "ci-ok" {
			others = append(others, name)
		}
	}
	assert.ElementsMatch(t, others, []string(ok.Needs))

	cond := strings.TrimSpace(ok.If)
	cond = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cond, "${{"), "}}"))
	assert.Equal(t, "always()", cond)
}

// ciOkScript returns ci-ok's step script and the env variable that carries toJSON(needs).
func ciOkScript(t *testing.T) (script, needsVar string) {
	t.Helper()
	ok := repoWorkflow(t, "ci.yml").job(t, "ci-ok")
	for _, s := range ok.Steps {
		for k, v := range s.Env {
			if strings.Contains(strings.ReplaceAll(v, " ", ""), "toJSON(needs)") {
				require.NotContains(t, s.Run, "${{", "the script must read needs from its environment only")
				return s.Run, k
			}
		}
	}
	require.Fail(t, "no ci-ok step receives toJSON(needs) in its environment")
	return "", ""
}

func needsJSON(t *testing.T, results map[string]string) string {
	t.Helper()
	needs := map[string]any{}
	for job, r := range results {
		needs[job] = map[string]any{"result": r, "outputs": map[string]string{}}
	}
	b, err := json.Marshal(needs)
	require.NoError(t, err)
	return string(b)
}

// C7 (AC 2): over each of the 4 results.
func TestCIWorkflow_CiOkScriptDecidesOverEveryResult(t *testing.T) {
	script, needsVar := ciOkScript(t)
	allSuccess := func() map[string]string {
		m := map[string]string{}
		for _, j := range ciGateJobs {
			m[j] = "success"
		}
		return m
	}

	t.Run("success", func(t *testing.T) {
		r := runStep(t, script, cleanEnv(needsVar+"="+needsJSON(t, allSuccess())))
		assert.Equal(t, 0, r.code, r.output())
	})

	for _, result := range []string{"failure", "cancelled", "skipped"} {
		t.Run(result, func(t *testing.T) {
			needs := allSuccess()
			needs["test-integration"] = result
			r := runStep(t, script, cleanEnv(needsVar+"="+needsJSON(t, needs)))
			assert.Equal(t, 1, r.code, r.output())
			assert.Regexp(t, `(?m)test-integration\W.*\b`+result+`\b`, r.output())
		})
	}

	t.Run("names every job that did not succeed", func(t *testing.T) {
		needs := allSuccess()
		needs["lint"] = "failure"
		needs["preload"] = "cancelled"
		needs["govulncheck"] = "skipped"
		r := runStep(t, script, cleanEnv(needsVar+"="+needsJSON(t, needs)))
		assert.Equal(t, 1, r.code, r.output())
		assert.Regexp(t, `(?m)lint\W.*\bfailure\b`, r.output())
		assert.Regexp(t, `(?m)preload\W.*\bcancelled\b`, r.output())
		assert.Regexp(t, `(?m)govulncheck\W.*\bskipped\b`, r.output())
		assert.NotContains(t, r.output(), "build")
	})
}

// C9 (AC 3)
func TestCIWorkflow_LintFailsWhenGoFmtRewritesAFile(t *testing.T) {
	lint := repoWorkflow(t, "ci.yml").job(t, "lint")
	makeLint := stepIndex(lint, runLine("make lint"))
	diff := stepIndex(lint, regexp.MustCompile(`git diff --exit-code --name-only(?:\s|;|$)`))
	require.GreaterOrEqual(t, makeLint, 0, "lint does not run make lint")
	require.GreaterOrEqual(t, diff, 0, "lint does not run git diff --exit-code --name-only")
	assert.Greater(t, diff, makeLint, "git diff must run after make lint")
	assert.NotContains(t, lint.Steps[diff].Run, "git diff --exit-code --name-only --", "the diff must cover every tracked file")
}

// C10 (AC 4)
func TestCIWorkflow_LintRunsMakeLintWithGolangciLintV2_13_2(t *testing.T) {
	lint := repoWorkflow(t, "ci.yml").job(t, "lint")
	install, ok := stepUsing(lint, "golangci/golangci-lint-action@")
	require.True(t, ok, "lint does not install golangci-lint")
	assert.Equal(t, "v2.13.2", install.With["version"])
	assert.GreaterOrEqual(t, stepIndex(lint, runLine("make lint")), 0, "lint does not run make lint")
}

// C11 (AC 5)
func TestCIWorkflow_BuildMatrixRunsMakeBuildForStaticAndDynamic(t *testing.T) {
	build := repoWorkflow(t, "ci.yml").job(t, "build")
	assert.Equal(t, []any{"static", "dynamic"}, build.Strategy.Matrix["link_mode"])
	assert.GreaterOrEqual(t, stepIndex(build, regexp.MustCompile(`(?m)^\s*make build LINK_MODE=\$\{\{\s*matrix\.link_mode\s*\}\}\s*$`)), 0,
		"build does not run make build LINK_MODE=<leg>")
}

// C12 (AC 6)
func TestCIWorkflow_TestJobRunsMakeTest(t *testing.T) {
	assert.GreaterOrEqual(t, stepIndex(repoWorkflow(t, "ci.yml").job(t, "test"), runLine("make test")), 0)
}

// C13 (AC 7, AC 8)
func TestCIWorkflow_TestIntegrationRunsAsRootWithTshark(t *testing.T) {
	it := repoWorkflow(t, "ci.yml").job(t, "test-integration")
	install := stepIndex(it, regexp.MustCompile(`apt-get install\b[^\n]*\btshark\b`))
	runIT := stepIndex(it, runLine(`sudo -E env "PATH=$PATH" make test-integration`))
	require.GreaterOrEqual(t, install, 0, "test-integration does not install tshark")
	require.GreaterOrEqual(t, runIT, 0, "test-integration does not run the tests as root")
	assert.Greater(t, runIT, install)
}

// C16 (AC 9)
func TestCIWorkflow_GenerateDriftDiffsTheFourGeneratedFiles(t *testing.T) {
	gd := repoWorkflow(t, "ci.yml").job(t, "generate-drift")
	gen := stepIndex(gd, runLine("make generate"))
	diff := stepIndex(gd, regexp.MustCompile(`git diff --exit-code --name-only -- bpf/(?:\s|;|$)`))
	require.GreaterOrEqual(t, gen, 0, "generate-drift does not run make generate")
	require.GreaterOrEqual(t, diff, 0, "generate-drift does not diff bpf/")
	assert.Greater(t, diff, gen)

	// The diff covers the four generated files: each is tracked under bpf/.
	for _, f := range []string{"bpf/proxy_bpfel.go", "bpf/proxy_bpfeb.go", "bpf/proxy_bpfel.o", "bpf/proxy_bpfeb.o"} {
		assert.FileExists(t, repoPath(t, f))
	}
}

// C17 (AC 10)
func TestCIWorkflow_PreloadRunsMakeBuildPreload(t *testing.T) {
	pre := repoWorkflow(t, "ci.yml").job(t, "preload")
	install := stepIndex(pre, regexp.MustCompile(`apt-get install\b[^\n]*\blibssl-dev\b`))
	build := stepIndex(pre, runLine("make build-preload"))
	require.GreaterOrEqual(t, install, 0, "preload does not install libssl-dev")
	require.GreaterOrEqual(t, build, 0, "preload does not run make build-preload")
	assert.Greater(t, build, install)
}

// C18 (AC 11)
func TestCIWorkflow_GovulncheckJobRunsMakeVuln(t *testing.T) {
	assert.GreaterOrEqual(t, stepIndex(repoWorkflow(t, "ci.yml").job(t, "govulncheck"), runLine("make vuln")), 0)
}
