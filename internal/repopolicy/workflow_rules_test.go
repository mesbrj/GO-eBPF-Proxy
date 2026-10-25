package repopolicy

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// violation is one breach of a workflow rule. String names the rule and the
// file, which is what a failing test job prints (AC 28).
type violation struct {
	rule, file, detail string
}

func (v violation) String() string {
	return fmt.Sprintf("%s violated in %s: %s", v.rule, v.file, v.detail)
}

// workflowRule is one of the plan's workflow invariants, checked over every
// file of a .github/workflows directory.
type workflowRule struct {
	id    string
	check func(files []workflowFile) []violation
}

// workflowRules are the rules of AC 12 to AC 15 and AC 19 to AC 24.
var workflowRules = []workflowRule{
	{"AC 12", ruleGoFromFixedSpec},
	{"AC 13", ruleCINoSecretOnlyContentsRead},
	{"AC 14", ruleCIUploadsNoArtifact},
	{"AC 15", ruleUsesPinnedToSHA},
	{"AC 19", ruleNoPullRequestTargetOrWorkflowRun},
	{"AC 20", ruleTopLevelPermissions},
	{"AC 21", ruleReviewEnvironmentsOneJobEach},
	{"AC 22", ruleClaudeCodeActionIsAnthropics},
	{"AC 23", ruleNeverMergeOrApprove},
	{"AC 24", ruleRunsOnUbuntu2404},
}

func checkWorkflowRules(files []workflowFile) []violation {
	var out []violation
	for _, r := range workflowRules {
		out = append(out, runRule(r, files)...)
	}
	return out
}

func runRule(r workflowRule, files []workflowFile) []violation {
	vs := r.check(files)
	for i := range vs {
		vs[i].rule = r.id
	}
	return vs
}

func ruleByID(t *testing.T, id string) workflowRule {
	t.Helper()
	for _, r := range workflowRules {
		if r.id == id {
			return r
		}
	}
	require.Failf(t, "no such rule", "%s", id)
	return workflowRule{}
}

// assertRuleHolds runs one rule over the committed workflows.
func assertRuleHolds(t *testing.T, id string) {
	t.Helper()
	for _, v := range runRule(ruleByID(t, id), repoWorkflows(t)) {
		assert.Fail(t, v.String())
	}
}

func ciFile(files []workflowFile) (workflowFile, []violation) {
	f, ok := findWorkflow(files, "ci.yml")
	if !ok {
		return f, []violation{{file: "ci.yml", detail: "ci.yml is missing"}}
	}
	return f, nil
}

// goRunRE matches a run: script that needs a Go toolchain: a Makefile target
// that runs go, or go itself. make build-preload needs only a C compiler.
var goRunRE = regexp.MustCompile(`\bmake\s+(?:lint|lint-workflows|build|test|test-integration|generate|vuln)(?:\s|$)|\bgo\s+(?:build|generate|install|run|test|vet)\b`)

func jobRunsGo(j job) bool {
	return stepIndex(j, goRunRE) >= 0
}

// AC 12: every ci.yml job that runs Go installs the latest 1.27.x from that
// fixed spec, never from go.mod, and no job has a Go version matrix.
func ruleGoFromFixedSpec(files []workflowFile) []violation {
	f, vs := ciFile(files)
	if vs != nil {
		return vs
	}
	var out []violation
	add := func(format string, args ...any) {
		out = append(out, violation{file: f.name, detail: fmt.Sprintf(format, args...)})
	}
	for _, name := range f.jobNames() {
		j := f.wf.Jobs[name]
		setups := 0
		for _, s := range j.Steps {
			if !strings.HasPrefix(s.Uses, "actions/setup-go@") {
				continue
			}
			setups++
			if v := fmt.Sprint(s.With["go-version"]); v != "1.27.x" {
				add("job %s: setup-go go-version is %q, want 1.27.x", name, v)
			}
			if v := fmt.Sprint(s.With["check-latest"]); v != "true" {
				add("job %s: setup-go check-latest is %q, want true", name, v)
			}
			if _, ok := s.With["go-version-file"]; ok {
				add("job %s: setup-go reads go-version-file", name)
			}
		}
		if jobRunsGo(j) && setups == 0 {
			add("job %s runs Go without actions/setup-go", name)
		}
		for key := range j.Strategy.Matrix {
			if strings.Contains(strings.ToLower(key), "go") {
				add("job %s has a Go version matrix (%s)", name, key)
			}
		}
	}
	return out
}

var secretRefRE = regexp.MustCompile(`\bsecrets\s*(?:\.|\[)`)

func isContentsReadOnly(perms any) bool {
	m, ok := perms.(map[string]any)
	return ok && len(m) == 1 && m["contents"] == "read"
}

// AC 13: ci.yml references no secret and grants GITHUB_TOKEN contents: read only.
func ruleCINoSecretOnlyContentsRead(files []workflowFile) []violation {
	f, vs := ciFile(files)
	if vs != nil {
		return vs
	}
	var out []violation
	if loc := secretRefRE.FindIndex(f.raw); loc != nil {
		out = append(out, violation{file: f.name, detail: fmt.Sprintf("references a secret: %q", f.raw[loc[0]:loc[1]])})
	}
	if !isContentsReadOnly(f.wf.Permissions) {
		out = append(out, violation{file: f.name, detail: fmt.Sprintf("top-level permissions are %v, want only contents: read", f.wf.Permissions)})
	}
	for _, name := range f.jobNames() {
		if p := f.wf.Jobs[name].Permissions; p != nil && !isContentsReadOnly(p) {
			out = append(out, violation{file: f.name, detail: fmt.Sprintf("job %s grants permissions %v", name, p)})
		}
	}
	return out
}

// AC 14: ci.yml uploads no artifact.
func ruleCIUploadsNoArtifact(files []workflowFile) []violation {
	f, vs := ciFile(files)
	if vs != nil {
		return vs
	}
	var out []violation
	for _, name := range f.jobNames() {
		if s, ok := stepUsing(f.wf.Jobs[name], "actions/upload-artifact@"); ok {
			out = append(out, violation{file: f.name, detail: fmt.Sprintf("job %s uploads an artifact with %s", name, s.Uses)})
		}
	}
	return out
}

var pinnedUsesRE = regexp.MustCompile(`^[^@]+@[0-9a-f]{40} # v[0-9]`)

// AC 15: every non-local uses: pins a 40-hex commit SHA with a # v<version> comment.
func ruleUsesPinnedToSHA(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		for _, u := range allUses(f.root) {
			if strings.HasPrefix(u.value, "./") {
				continue
			}
			if !pinnedUsesRE.MatchString(u.value + " " + u.comment) {
				out = append(out, violation{file: f.name, detail: fmt.Sprintf("uses %q %q is not pinned to a commit SHA with a # v<version> comment", u.value, u.comment)})
			}
		}
	}
	return out
}

// AC 19: no pull_request_target and no workflow_run trigger.
func ruleNoPullRequestTargetOrWorkflowRun(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		for _, ev := range []string{"pull_request_target", "workflow_run"} {
			if _, ok := triggers(f.wf)[ev]; ok {
				out = append(out, violation{file: f.name, detail: "triggers on " + ev})
			}
		}
	}
	return out
}

// AC 20: every workflow declares a top-level permissions block.
func ruleTopLevelPermissions(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		if mappingValue(f.root, "permissions") == nil {
			out = append(out, violation{file: f.name, detail: "no top-level permissions block"})
		}
	}
	return out
}

// reviewEnvironments maps each review environment to the one job allowed to use it.
var reviewEnvironments = map[string][2]string{
	"claude-review": {"review.yml", "judge"},
	"review-bot":    {"review.yml", "post"},
}

// AC 21: claude-review and review-bot are each referenced by exactly one job,
// review.yml's judge and post respectively.
func ruleReviewEnvironmentsOneJobEach(files []workflowFile) []violation {
	var out []violation
	for _, env := range []string{"claude-review", "review-bot"} {
		want := reviewEnvironments[env]
		found := false
		for _, f := range files {
			for _, name := range f.jobNames() {
				if environmentName(f.wf.Jobs[name].Environment) != env {
					continue
				}
				if f.name == want[0] && name == want[1] {
					found = true
					continue
				}
				out = append(out, violation{file: f.name, detail: fmt.Sprintf("job %s references environment %s, which only %s's %s may use", name, env, want[0], want[1])})
			}
		}
		if !found {
			out = append(out, violation{file: want[0], detail: fmt.Sprintf("job %s does not reference environment %s", want[1], env)})
		}
	}
	return out
}

// AC 22: claude-code-action always comes from the anthropics owner.
func ruleClaudeCodeActionIsAnthropics(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		for _, u := range allUses(f.root) {
			if owner, repo := usesRepo(u.value); repo == "claude-code-action" && owner != "anthropics" {
				out = append(out, violation{file: f.name, detail: fmt.Sprintf("uses %s, whose owner is not anthropics", u.value)})
			}
		}
	}
	return out
}

// mergeApproveForms are the 5 forms of AC 23.
var mergeApproveForms = []struct {
	name string
	re   *regexp.Regexp
}{
	{"gh pr merge", regexp.MustCompile(`gh\s+pr\s+merge\b`)},
	{"auto-merge enablement", regexp.MustCompile(`gh\s+pr\s+merge\b[^\n]*--auto|(?i)enablePullRequestAutoMerge|uses:\s*\S*auto-?merge`)},
	{"gh pr review --approve", regexp.MustCompile(`gh\s+pr\s+review\b[^\n]*(?:--approve|\s-a\b)`)},
	{"APPROVE review event", regexp.MustCompile(`["']?\bevent["']?\s*[:=]\s*["']?APPROVE\b`)},
	{"auto-approve action", regexp.MustCompile(`(?i)uses:\s*\S*approve`)},
}

// AC 23: no merge, no auto-merge enablement, no approving review.
func ruleNeverMergeOrApprove(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		for _, form := range mergeApproveForms {
			if loc := form.re.FindIndex(f.raw); loc != nil {
				out = append(out, violation{file: f.name, detail: fmt.Sprintf("contains %s: %q", form.name, f.raw[loc[0]:loc[1]])})
			}
		}
	}
	return out
}

// AC 24: every job runs on ubuntu-24.04.
func ruleRunsOnUbuntu2404(files []workflowFile) []violation {
	var out []violation
	for _, f := range files {
		for _, name := range f.jobNames() {
			if r := f.wf.Jobs[name].RunsOn; r != "ubuntu-24.04" {
				out = append(out, violation{file: f.name, detail: fmt.Sprintf("job %s runs on %v, want ubuntu-24.04", name, r)})
			}
		}
	}
	return out
}

// AC 28: a change under .github that breaks a rule fails make test, naming the
// rule and the file.
func TestWorkflowRules_HoldForCommittedWorkflows(t *testing.T) {
	for _, v := range checkWorkflowRules(repoWorkflows(t)) {
		assert.Fail(t, v.String())
	}
}

// C19 (AC 12)
func TestCIWorkflow_GoIs1_27xFromAFixedSpec(t *testing.T) {
	assertRuleHolds(t, "AC 12")

	ci := repoWorkflow(t, "ci.yml")
	var goJobs []string
	for _, name := range ci.jobNames() {
		if jobRunsGo(ci.wf.Jobs[name]) {
			goJobs = append(goJobs, name)
		}
	}
	assert.ElementsMatch(t, []string{"workflow-lint", "lint", "build", "test", "test-integration", "generate-drift", "govulncheck"}, goJobs,
		"the jobs that run Go, each of which the rule requires to install 1.27.x")
}

// C20 (AC 13)
func TestCIWorkflow_ReferencesNoSecretAndOnlyContentsRead(t *testing.T) {
	assertRuleHolds(t, "AC 13")
	ci := repoWorkflow(t, "ci.yml")
	assert.Equal(t, map[string]any{"contents": "read"}, ci.wf.Permissions)
	assert.NotRegexp(t, secretRefRE, string(ci.raw))
}

// C21 (AC 14)
func TestCIWorkflow_UploadsNoArtifact(t *testing.T) {
	assertRuleHolds(t, "AC 14")
	assert.NotContains(t, string(repoWorkflow(t, "ci.yml").raw), "upload-artifact")
}

// C22 (AC 15, door 2)
func TestWorkflows_PinEveryUsesToACommitSHAWithVersionComment(t *testing.T) {
	assertRuleHolds(t, "AC 15")
	n := 0
	for _, f := range repoWorkflows(t) {
		n += len(allUses(f.root))
	}
	assert.Positive(t, n, "the workflows use no action at all, so the rule checked nothing")
}

// C26 (AC 19)
func TestWorkflows_DeclareNoPullRequestTargetOrWorkflowRun(t *testing.T) {
	assertRuleHolds(t, "AC 19")
}

// C27 (AC 20)
func TestWorkflows_DeclareTopLevelPermissions(t *testing.T) {
	assertRuleHolds(t, "AC 20")
}

// C28 (AC 21, door 3)
func TestWorkflows_EachReviewEnvironmentHasExactlyOneJob(t *testing.T) {
	assertRuleHolds(t, "AC 21")
	review := repoWorkflow(t, "review.yml")
	assert.Equal(t, "claude-review", environmentName(review.job(t, "judge").Environment))
	assert.Equal(t, "review-bot", environmentName(review.job(t, "post").Environment))
}

// C29 (AC 22)
func TestWorkflows_ClaudeCodeActionIsAnthropics(t *testing.T) {
	assertRuleHolds(t, "AC 22")
	n := 0
	for _, f := range repoWorkflows(t) {
		for _, u := range allUses(f.root) {
			if _, repo := usesRepo(u.value); repo == "claude-code-action" {
				n++
			}
		}
	}
	assert.Equal(t, 1, n, "claude-code-action steps across the workflows")
}

// C30 (AC 23): the committed workflows carry none of the 5 forms, and each
// form is one the rule detects.
func TestWorkflows_NeverMergeOrApprove(t *testing.T) {
	assertRuleHolds(t, "AC 23")

	samples := map[string]string{
		"gh pr merge":            "      - run: gh pr merge \"$PR\" --squash\n",
		"auto-merge enablement":  "      - uses: peter-evans/enable-pull-request-automerge@0000000000000000000000000000000000000000 # v3.0.0\n",
		"gh pr review --approve": "      - run: gh pr review \"$PR\" --approve\n",
		"APPROVE review event":   "          payload='{\"event\": \"APPROVE\"}'\n",
		"auto-approve action":    "      - uses: hmarr/auto-approve-action@0000000000000000000000000000000000000000 # v4.0.0\n",
	}
	require.Len(t, samples, len(mergeApproveForms))
	for _, form := range mergeApproveForms {
		sample, ok := samples[form.name]
		require.True(t, ok, "no sample for %s", form.name)
		assert.Regexp(t, form.re, sample, "form %s is not detected", form.name)
	}
}

// C31 (AC 24)
func TestWorkflows_EveryJobRunsOnUbuntu2404(t *testing.T) {
	assertRuleHolds(t, "AC 24")
	n := 0
	for _, f := range repoWorkflows(t) {
		n += len(f.wf.Jobs)
	}
	assert.Equal(t, 12, n, "jobs across ci.yml (9), review.yml (2) and platform-e2e.yml (1)")
}

// C35 (AC 28): each of the 10 rules, broken alone in a copy of the workflows,
// is reported by that rule alone, naming the rule and the file.
func TestWorkflowRules_EachViolationIsReportedWithRuleAndFile(t *testing.T) {
	cases := []struct {
		rule, file string
		mutate     func(t *testing.T, dir string)
	}{
		{"AC 12", "ci.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "ci.yml", "go-version: 1.27.x", "go-version: 1.26.x")
		}},
		{"AC 13", "ci.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "ci.yml", "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  pull-requests: write\n")
		}},
		{"AC 14", "ci.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "ci.yml", "      - run: make vuln\n",
				"      - run: make vuln\n      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n        with:\n          name: capture\n          path: dump.pcapng\n")
		}},
		{"AC 15", "ci.yml", func(t *testing.T, dir string) {
			mutateFileRegexp(t, dir, "ci.yml", `actions/checkout@[0-9a-f]{40} # v\S+`, "actions/checkout@v7")
		}},
		{"AC 19", "review.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "review.yml", "on:\n  pull_request:\n", "on:\n  pull_request_target:\n  pull_request:\n")
		}},
		{"AC 20", "platform-e2e.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "platform-e2e.yml", "permissions: {}\n", "")
		}},
		{"AC 21", "ci.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "ci.yml", "  govulncheck:\n    runs-on: ubuntu-24.04\n", "  govulncheck:\n    runs-on: ubuntu-24.04\n    environment: claude-review\n")
		}},
		{"AC 22", "review.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "review.yml", "anthropics/claude-code-action@", "someone-else/claude-code-action@")
		}},
		{"AC 23", "platform-e2e.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "platform-e2e.yml", "          exit 1\n", "          gh pr merge --squash\n          exit 1\n")
		}},
		{"AC 24", "ci.yml", func(t *testing.T, dir string) {
			mutateFile(t, dir, "ci.yml", "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest")
		}},
	}
	require.Len(t, cases, len(workflowRules))

	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			dir := copyWorkflows(t, t.TempDir())
			require.Empty(t, checkWorkflowRules(loadWorkflowDir(t, dir)), "the unmodified copy must hold every rule")

			tc.mutate(t, dir)
			vs := checkWorkflowRules(loadWorkflowDir(t, dir))
			require.NotEmpty(t, vs, "breaking %s went unreported", tc.rule)
			for _, v := range vs {
				assert.Equal(t, tc.rule, v.rule, "another rule fired: %s", v)
				assert.Equal(t, tc.file, v.file, "wrong file named: %s", v)
				assert.Contains(t, v.String(), tc.rule)
				assert.Contains(t, v.String(), tc.file)
			}
		})
	}
}
