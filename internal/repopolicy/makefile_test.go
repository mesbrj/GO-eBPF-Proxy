package repopolicy

import (
	"os/exec"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeIn runs the repository's Makefile with dir as the working directory.
func makeIn(t *testing.T, dir string, args ...string) result {
	t.Helper()
	cmd := exec.Command("make", append([]string{"-f", repoPath(t, "Makefile"), "-C", dir}, args...)...) // #nosec G204 -- make targets named by the test
	cmd.Env = cleanEnv()
	return run(t, cmd)
}

// C24 (AC 17)
func TestMakefile_LintWorkflowsFailsOnActionlintError(t *testing.T) {
	dir := t.TempDir()
	wfDir := copyWorkflows(t, dir)

	clean := makeIn(t, dir, "lint-workflows")
	require.Equal(t, 0, clean.code, "the committed workflows must lint clean:\n%s", clean.output())

	mutateFile(t, wfDir, "ci.yml", "      - govulncheck\n    runs-on:", "      - govulncheck\n      - no-such-job\n    runs-on:")
	broken := makeIn(t, dir, "lint-workflows")
	assert.Equal(t, 2, broken.code, broken.output())
	assert.Contains(t, broken.output(), "no-such-job", "actionlint's error names the missing job")
	assert.NotContains(t, broken.output(), "uvx zizmor", "make stops at actionlint's failure")
}

// C25 (AC 18, door 2): actionlint accepts a tag pin, zizmor's default
// unpinned-uses policy rejects it.
func TestMakefile_LintWorkflowsFailsOnZizmorFinding(t *testing.T) {
	dir := t.TempDir()
	wfDir := copyWorkflows(t, dir)
	mutateFileRegexp(t, wfDir, "ci.yml", `actions/checkout@[0-9a-f]{40} # v\S+`, "actions/checkout@v4")

	r := makeIn(t, dir, "lint-workflows")
	assert.Equal(t, 2, r.code, r.output())
	assert.Contains(t, r.output(), "uvx zizmor", "actionlint passed, so zizmor ran")
	assert.Contains(t, r.output(), "unpinned-uses")
}

var semverRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

// C32 (AC 25, door 9)
func TestMakefile_LintWorkflowsAndVulnRunPinnedVersions(t *testing.T) {
	recipes := []struct {
		variable string
		line     *regexp.Regexp
	}{
		{"ACTIONLINT_VERSION", regexp.MustCompile(`(?m)^go run github\.com/rhysd/actionlint/cmd/actionlint@(\S+) `)},
		{"ZIZMOR_VERSION", regexp.MustCompile(`(?m)^uvx zizmor@(\S+) `)},
		{"GOVULNCHECK_VERSION", regexp.MustCompile(`(?m)^go run golang\.org/x/vuln/cmd/govulncheck@(\S+) \./\.\.\.$`)},
	}

	makefile := string(readRepoFile(t, "Makefile"))
	dry := makeIn(t, repoRoot(t), "-n", "lint-workflows", "vuln")
	require.Equal(t, 0, dry.code, dry.output())
	for _, r := range recipes {
		m := r.line.FindStringSubmatch(dry.stdout)
		require.NotNil(t, m, "no %s recipe line in:\n%s", r.variable, dry.stdout)
		assert.Regexp(t, semverRE, m[1], "%s is not a concrete version", r.variable)
		assert.NotEqual(t, "latest", m[1])

		def := regexp.MustCompile(`(?m)^` + r.variable + `\s*:?=\s*(\S+)\s*$`).FindStringSubmatch(makefile)
		require.NotNil(t, def, "the Makefile does not define %s", r.variable)
		assert.Equal(t, def[1], m[1], "the recipe does not run the version held in %s", r.variable)
	}

	// The recipes take their version from the variable, so an override moves it.
	over := makeIn(t, repoRoot(t), "-n", "lint-workflows", "vuln",
		"ACTIONLINT_VERSION=v0.0.1", "ZIZMOR_VERSION=0.0.2", "GOVULNCHECK_VERSION=v0.0.3")
	require.Equal(t, 0, over.code, over.output())
	for i, want := range []string{"v0.0.1", "0.0.2", "v0.0.3"} {
		m := recipes[i].line.FindStringSubmatch(over.stdout)
		require.NotNil(t, m)
		assert.Equal(t, want, m[1])
	}
}

// C33 (AC 26)
func TestMakefile_CheckRunsLintWorkflowsAndVuln(t *testing.T) {
	dry := makeIn(t, repoRoot(t), "-n", "check")
	require.Equal(t, 0, dry.code, dry.output())
	assert.Regexp(t, `(?m)^go run github\.com/rhysd/actionlint/cmd/actionlint@\S+ \.github/workflows/`, dry.stdout)
	assert.Regexp(t, `(?m)^uvx zizmor@\S+ \.github/workflows/`, dry.stdout)
	assert.Regexp(t, `(?m)^go run golang\.org/x/vuln/cmd/govulncheck@\S+ \./\.\.\.$`, dry.stdout)
}

// C34 (AC 27, door 9)
func TestGoMod_HasNoToolDirective(t *testing.T) {
	gomod := string(readRepoFile(t, "go.mod"))
	require.Regexp(t, `(?m)^module github\.com/mesbrj/GO-eBPF-Proxy$`, gomod)
	assert.NotRegexp(t, `(?m)^\s*tool(?:\s|\()`, gomod)
}
