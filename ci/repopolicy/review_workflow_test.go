package repopolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// C37 (AC 29, AC 30)
func TestReviewWorkflow_TriggersOnOpenedReopenedReadyAndDispatch(t *testing.T) {
	on := triggers(repoWorkflow(t, "review.yml").wf)
	assert.ElementsMatch(t, []string{"pull_request", "workflow_dispatch"}, keys(on))

	pr, ok := on["pull_request"].(map[string]any)
	require.True(t, ok, "pull_request has no configuration")
	assert.ElementsMatch(t, []any{"opened", "reopened", "ready_for_review"}, pr["types"])

	dispatch, ok := on["workflow_dispatch"].(map[string]any)
	require.True(t, ok, "workflow_dispatch has no configuration")
	inputs, ok := dispatch["inputs"].(map[string]any)
	require.True(t, ok, "workflow_dispatch has no inputs")
	assert.ElementsMatch(t, []string{"pr"}, keys(inputs))
	prInput, ok := inputs["pr"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, prInput["required"])
}

// C38 (AC 31): a push to a pull request is the synchronize activity type.
func TestReviewWorkflow_DoesNotTriggerOnSynchronize(t *testing.T) {
	on := triggers(repoWorkflow(t, "review.yml").wf)
	assert.NotContains(t, on, "push")
	pr, ok := on["pull_request"].(map[string]any)
	require.True(t, ok)
	types, ok := pr["types"].([]any)
	require.True(t, ok, "without types, pull_request includes synchronize")
	require.NotEmpty(t, types)
	assert.NotContains(t, types, "synchronize")
}

// guardStep returns judge's step that reads the pull request with gh pr view.
func guardStep(t *testing.T) step {
	t.Helper()
	judge := repoWorkflow(t, "review.yml").job(t, "judge")
	for _, s := range judge.Steps {
		if strings.Contains(s.Run, "gh pr view") {
			require.NotEmpty(t, s.ID, "the guard step needs an id for its output")
			return s
		}
	}
	require.Fail(t, "judge has no step that reads the pull request with gh pr view")
	return step{}
}

// C42 (AC 33, amended 2026-10-25): over each of the 3 conditions, on both
// paths; the post side is C79.
func TestReviewWorkflow_SkipsDraftDependabotAndForkPullRequests(t *testing.T) {
	review := repoWorkflow(t, "review.yml")
	judge := review.job(t, "judge")

	conditions := map[string]string{
		"draft":           "!github.event.pull_request.draft",
		"dependabot[bot]": "github.event.pull_request.user.login != 'dependabot[bot]'",
		"fork head":       "github.event.pull_request.head.repo.full_name == github.repository",
	}
	for name, cond := range conditions {
		assert.Contains(t, judge.If, cond, "judge's if: lacks the %s condition", name)
	}
	// Whole, so that a draft passing the if: (an || between the conditions) or
	// a pull_request path that never runs (&& with the dispatch path) fails.
	wantIf := "github.event_name == 'workflow_dispatch' || (" +
		conditions["draft"] + " && " + conditions["dependabot[bot]"] + " && " + conditions["fork head"] + ")"
	gotIf := strings.TrimSpace(judge.If)
	gotIf = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(gotIf, "${{"), "}}"))
	assert.Equal(t, wantIf, strings.Join(strings.Fields(gotIf), " "), "judge's if:")

	// The dispatch path: the guard step decides, and every later judge step
	// waits on its output, so nothing is uploaded for post to find.
	guard := guardStep(t)
	gate := "steps." + guard.ID + ".outputs.eligible == 'true'"
	afterGuard := false
	for _, s := range judge.Steps {
		if s.ID == guard.ID {
			afterGuard = true
			continue
		}
		require.True(t, afterGuard, "a judge step runs before the guard: %q", s.Name)
		assert.Equal(t, gate, strings.TrimSpace(s.If), "judge step %q does not wait on the guard", s.Name)
	}

	cases := []struct {
		name, pr string
		eligible bool
	}{
		{"open pull request from this repository", `{"number":7,"state":"OPEN","isDraft":false,"author":{"login":"mesbrj"},"isCrossRepository":false,"headRefOid":"0123456789abcdef0123456789abcdef01234567"}`, true},
		{"draft", `{"number":7,"state":"OPEN","isDraft":true,"author":{"login":"mesbrj"},"isCrossRepository":false,"headRefOid":"0123456789abcdef0123456789abcdef01234567"}`, false},
		{"dependabot[bot]", `{"number":7,"state":"OPEN","isDraft":false,"author":{"is_bot":true,"login":"app/dependabot"},"isCrossRepository":false,"headRefOid":"0123456789abcdef0123456789abcdef01234567"}`, false},
		{"fork head", `{"number":7,"state":"OPEN","isDraft":false,"author":{"login":"someone"},"isCrossRepository":true,"headRefOid":"0123456789abcdef0123456789abcdef01234567"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh := newFakeGH(t, map[string]ghResponse{"pr view": {Stdout: tc.pr}})
			out := filepath.Join(t.TempDir(), "github_output")
			require.NoError(t, os.WriteFile(out, nil, 0o600))

			r := runStep(t, guard.Run, gh.env("PR=7", "GITHUB_REPOSITORY=mesbrj/GO-eBPF-Proxy", "GITHUB_OUTPUT="+out))
			require.Equal(t, 0, r.code, r.output())
			b, err := os.ReadFile(out) // #nosec G304 -- the temp output file this test created
			require.NoError(t, err)
			want := "eligible=false"
			if tc.eligible {
				want = "eligible=true"
			}
			assert.Contains(t, nonEmptyLines(string(b)), want)
			assert.Contains(t, nonEmptyLines(string(b)), "pr=7")

			calls := gh.calls()
			require.Len(t, calls, 1, "the guard reads the pull request once and writes nothing")
			assert.True(t, strings.HasPrefix(calls[0].Key, "pr view 7"), calls[0].Key)
		})
	}
}

// claudeCodeAction is the uses: prefix of judge's Claude step.
const claudeCodeAction = "anthropics/claude-code-action@"

// claudeStep returns judge's claude-code-action step.
func claudeStep(t *testing.T) step {
	t.Helper()
	s, ok := stepUsing(repoWorkflow(t, "review.yml").job(t, "judge"), claudeCodeAction)
	require.True(t, ok, "judge has no claude-code-action step")
	return s
}

// C43 (AC 34, door 3, door 5)
func TestReviewWorkflow_JudgeHasReadOnlyTokenAndNoAppToken(t *testing.T) {
	review := repoWorkflow(t, "review.yml")
	judge := review.job(t, "judge")

	assert.Equal(t, map[string]any{"contents": "read", "pull-requests": "read"}, judge.Permissions)
	assert.Equal(t, "${{ secrets.GITHUB_TOKEN }}", claudeStep(t).With["github_token"])
	_, mints := stepUsing(judge, "actions/create-github-app-token@")
	assert.False(t, mints, "judge mints an App token")
	assert.NotContains(t, nodeText(t, review.jobNode(t, "judge")), "REVIEW_BOT_")
}

// forbiddenClaudeCommands are the 6 Bash commands of AC 35.
var forbiddenClaudeCommands = []string{"gh api", "gh pr review", "gh pr comment", "gh pr edit", "gh pr merge", "git push"}

// judgeAllowedTools is door 5's closed list of judge's --allowedTools rules
// (plan.md, Landing, door 5 amended again 2026-10-25): Edit(/findings.json),
// then "the other rules stay".
var judgeAllowedTools = []string{
	"Read",
	"Glob",
	"Grep",
	"Edit(/findings.json)",
	"WebFetch",
	"WebSearch",
	"Bash(gh pr view:*)",
	"Bash(gh pr diff:*)",
	"Bash(gh pr checks:*)",
	"Bash(python3 .claude/skills/the-judge/scripts/review_gate.py findings.json)",
}

// shellWords splits s into words at blanks outside single or double quotes,
// removing the quotes. Any other shell syntax is kept as written, which can
// make a rule differ from door 5's but never hides one.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case unicode.IsSpace(r):
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
			}
			inWord = false
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// allowedToolsValues returns every value claude_args passes with
// --allowedTools or --allowed-tools. claude-code-action (f27be6b,
// base-action/src/parse-sdk-options.ts) takes each word after such a flag up
// to the next word starting with -- as one of its values, every occurrence of
// the flag adding to the list. Words after --allowedTools=<value> count too,
// which can only add rules.
func allowedToolsValues(args string) []string {
	words := shellWords(args)
	var values []string
	for i := 0; i < len(words); i++ {
		flag, inline, hasInline := strings.Cut(words[i], "=")
		if flag != "--allowedTools" && flag != "--allowed-tools" {
			continue
		}
		if hasInline {
			values = append(values, inline)
		}
		for i+1 < len(words) && !strings.HasPrefix(words[i+1], "--") {
			i++
			values = append(values, words[i])
		}
	}
	return values
}

// splitRules splits an --allowedTools value at each of seps outside
// parentheses, trimming blanks and dropping empty rules.
func splitRules(v, seps string) []string {
	var rules []string
	depth, cur := 0, strings.Builder{}
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			rules = append(rules, s)
		}
		cur.Reset()
	}
	for _, r := range v {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case strings.ContainsRune(seps, r) && depth == 0:
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()
	return rules
}

// allowedTools collects every rule passed with --allowedTools (or
// --allowed-tools) in claude_args. Rules are separated by commas or spaces
// outside parentheses.
func allowedTools(args string) []string {
	var rules []string
	for _, v := range allowedToolsValues(args) {
		rules = append(rules, splitRules(v, ", ")...)
	}
	return rules
}

// admits reports whether an allow rule lets Claude run cmd. Bash and Bash(*)
// admit everything; Bash(prefix:*) admits commands starting with prefix; any
// other * is a wildcard; otherwise the command must match exactly.
func admits(rule, cmd string) bool {
	if rule == "Bash" {
		return true
	}
	if !strings.HasPrefix(rule, "Bash(") || !strings.HasSuffix(rule, ")") {
		return false
	}
	pattern := strings.TrimSuffix(strings.TrimPrefix(rule, "Bash("), ")")
	if prefix, ok := strings.CutSuffix(pattern, ":*"); ok {
		return strings.HasPrefix(cmd, prefix)
	}
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(cmd)
}

// C44 (AC 35): over each of the 6 commands.
func TestReviewWorkflow_ClaudeStepAllowsNoGitHubWriteCommand(t *testing.T) {
	args, _ := claudeStep(t).With["claude_args"].(string)
	rules := allowedTools(args)
	require.NotEmpty(t, rules, "claude_args passes no --allowedTools")

	for _, cmd := range forbiddenClaudeCommands {
		t.Run(cmd, func(t *testing.T) {
			for _, sample := range []string{cmd, cmd + " repos/mesbrj/GO-eBPF-Proxy/pulls/1/reviews --method POST"} {
				for _, rule := range rules {
					assert.False(t, admits(rule, sample), "rule %q admits %q", rule, sample)
				}
			}
		})
	}

	// admits recognises the shapes it must refuse.
	for _, rule := range []string{"Bash", "Bash(*)", "Bash(gh:*)", "Bash(gh pr *)", "Bash(git push:*)"} {
		assert.True(t, admits(rule, "gh pr merge 1") || admits(rule, "git push origin"), "%s", rule)
	}
}

// C83 (door 5 amended 2026-10-25): Claude changes no file it can execute,
// and it can still write findings.json and run the gate on it.
func TestReviewWorkflow_ClaudeCanWriteOnlyFindingsJSON(t *testing.T) {
	args, _ := claudeStep(t).With["claude_args"].(string)
	rules := allowedTools(args)
	require.NotEmpty(t, rules, "claude_args passes no --allowedTools")

	// Claude Code checks each file-writing tool against Edit(path) rules only;
	// a /path rule given on the command line anchors at the checkout root.
	var writeRules []string
	for _, rule := range rules {
		switch tool, _, _ := strings.Cut(rule, "("); tool {
		case "Write", "Edit", "MultiEdit", "NotebookEdit":
			writeRules = append(writeRules, rule)
		}
	}
	assert.Equal(t, []string{"Edit(/findings.json)"}, writeRules, "the file-writing rules")

	const gate = ".claude/skills/the-judge/scripts/review_gate.py"
	refused := []string{"python3 -c pass", "python3 " + gate, "python3 " + gate + " other.json", "python3 .judge/scan.py"}
	for _, git := range []string{"git log", "git show", "git diff", "git blame"} {
		refused = append(refused, git+" --output="+gate, git+" -1 --output "+gate)
	}
	for _, cmd := range refused {
		for _, rule := range rules {
			assert.False(t, admits(rule, cmd), "rule %q admits %q", rule, cmd)
		}
	}

	runsGate := false
	for _, rule := range rules {
		runsGate = runsGate || admits(rule, "python3 "+gate+" findings.json")
	}
	assert.True(t, runsGate, "no rule lets Claude run the gate on findings.json")

	// Amended 2026-10-25 (fix round 2): the whole list, not a sample. Every
	// value of every --allowedTools or --allowed-tools flag, split on commas
	// outside parentheses, holds door 5's 10 rules, each once, and nothing else.
	require.Len(t, judgeAllowedTools, 10)
	var got []string
	for _, v := range allowedToolsValues(args) {
		got = append(got, splitRules(v, ",")...)
	}
	assert.ElementsMatch(t, judgeAllowedTools, got, "judge's --allowedTools rules against door 5's closed list")
}

// judgeModelArgs are the words claude_args passes before the allowlist (feature
// 09, door 3): judge's full model ID and effort, with no alias and no fallback.
var judgeModelArgs = []string{"--model", "claude-opus-5-5", "--effort", "high", "--allowedTools"}

// C85 (door 5, AC 34; fix round 3): door 5 rests on "an Agent SDK run with no
// permission mode", so the step passes nothing beside the model, the effort
// (feature 09's C10, which supersedes C85's two words) and the allowlist. A
// permission mode, a settings file or input, an env: or a second flag would
// each override or extend the rules C83 pins.
func TestReviewWorkflow_ClaudeStepInputsArePinned(t *testing.T) {
	// The step type keeps only the keys other checks read, so the step's own
	// keys come from its YAML node.
	stepsNode := mappingValue(repoWorkflow(t, "review.yml").jobNode(t, "judge"), "steps")
	require.NotNil(t, stepsNode, "judge has no steps")
	var steps, claude []map[string]any
	require.NoError(t, stepsNode.Decode(&steps))
	for _, s := range steps {
		if uses, _ := s["uses"].(string); strings.HasPrefix(uses, claudeCodeAction) {
			claude = append(claude, s)
		}
	}
	require.Len(t, claude, 1, "judge's claude-code-action steps")
	assert.ElementsMatch(t, []string{"name", "if", "uses", "with"}, keys(claude[0]), "the claude step's keys (no env)")

	with := claudeStep(t).With
	assert.ElementsMatch(t, []string{"claude_code_oauth_token", "github_token", "claude_args", "prompt"}, keys(with),
		"the claude step's with: inputs")

	args, ok := with["claude_args"].(string)
	require.True(t, ok, "claude_args is not a string")
	words := shellWords(args)
	n := len(judgeModelArgs)
	require.Len(t, words, n+1, "claude_args must be %q and one value: %q", judgeModelArgs, words)
	assert.Equal(t, judgeModelArgs, words[:n], "claude_args's words before the allowlist")
	require.Len(t, judgeAllowedTools, 10)
	assert.ElementsMatch(t, judgeAllowedTools, splitRules(words[n], ","), "the --allowedTools value's rules against door 5's closed list")
}

// statusFunction matches a call to any status check function. An if: that calls
// one, success() included, loses GitHub's implicit success(), so its step can
// run after the claude step failed, as with if: "!success()".
var statusFunction = regexp.MustCompile(`(?i)\b(success|always|failure|cancelled)\s*\(`)

// C14 (feature 09, AC 13): when the Opus session cannot complete, judge fails
// before it uploads findings, so review-post finds no artifact and posts
// nothing; no other model reviews in its place.
func TestReviewWorkflow_NoFindingsArtifactWhenClaudeFails(t *testing.T) {
	// continue-on-error is not a field of the step type, so the steps are
	// read from the job's YAML node.
	stepsNode := mappingValue(repoWorkflow(t, "review.yml").jobNode(t, "judge"), "steps")
	require.NotNil(t, stepsNode, "judge has no steps")
	var steps []map[string]any
	require.NoError(t, stepsNode.Decode(&steps))

	claude, upload := -1, -1
	for i, s := range steps {
		uses, _ := s["uses"].(string)
		switch {
		case strings.HasPrefix(uses, claudeCodeAction):
			require.Equal(t, -1, claude, "judge has more than one claude-code-action step")
			claude = i
		case strings.HasPrefix(uses, "actions/upload-artifact@"):
			if with, _ := s["with"].(map[string]any); with["name"] == "findings" {
				upload = i
			}
		}
	}
	require.NotEqual(t, -1, claude, "judge has no claude-code-action step")
	require.Greater(t, upload, claude, "judge must upload findings after the claude step")

	assert.NotContains(t, steps[claude], "continue-on-error", "the claude step's failure must fail judge")
	for _, s := range steps[claude+1:] {
		cond, _ := s["if"].(string)
		assert.False(t, statusFunction.MatchString(cond), "step %q runs after a failed claude step: if: %s", s["name"], cond)
	}

	with, _ := steps[claude]["with"].(map[string]any)
	args, _ := with["claude_args"].(string)
	for _, w := range shellWords(args) {
		assert.False(t, strings.HasPrefix(w, "--fallback-model"), "claude_args names a fallback model: %q", w)
	}
}

// judgeExecutedScripts are the SHA-256 digests of the files from the checked-out
// pull request that judge executes: the gather step runs scan_bypasses.py
// before Claude, and the gate command Claude may run executes review_gate.py.
var judgeExecutedScripts = map[string]string{ // #nosec G101 -- SHA-256 digests, not credentials
	"scan_bypasses.py": "dcef32fd8dd27cb88cfa325be50e270cf8774a7ec82d5aed2c87b91b534a6294",
	"review_gate.py":   "279f0a119907c6a0a178d2be7cb8b3f1a5642f99a83fc4008c92bfbf3faf486d",
}

// C86 (door 5, AC 34; fix round 4): door 5's "no permission mode" also rests
// on the rest of the run. A step, a job or workflow default, or a script from
// the pull request could write ~/.claude/settings.json before Claude starts,
// so the job is pinned whole against the golden copy and the scripts by hash.
func TestReviewWorkflow_JudgeJobIsPinned(t *testing.T) {
	review := repoWorkflow(t, "review.yml")

	raw, err := os.ReadFile(filepath.Join("testdata", "judge.golden.yml")) // #nosec G304 -- a fixture under testdata
	require.NoError(t, err)
	var want, got map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &want))
	require.NoError(t, review.jobNode(t, "judge").Decode(&got))
	assert.Equal(t, want, got, "judge against testdata/judge.golden.yml")

	defaults := mappingValue(review.root, "defaults")
	require.NotNil(t, defaults, "review.yml has no workflow-level defaults")
	var gotDefaults map[string]any
	require.NoError(t, defaults.Decode(&gotDefaults))
	assert.Equal(t, map[string]any{"run": map[string]any{"shell": "bash"}}, gotDefaults, "review.yml's workflow-level defaults")
	assert.Nil(t, mappingValue(review.root, "env"), "review.yml has a top-level env")

	require.Len(t, judgeExecutedScripts, 2)
	for name, want := range judgeExecutedScripts {
		sum := sha256.Sum256(readRepoFile(t, judgeScripts+"/"+name))
		assert.Equal(t, want, hex.EncodeToString(sum[:]), "SHA-256 of %s/%s", judgeScripts, name)
	}
}

// judgeSkillFiles are the only tracked paths with a .claude path component
// that door 5's restated caveat allows: the-judge's 7 files.
var judgeSkillFiles = []string{
	".claude/skills/the-judge/.skill-meta.json",
	".claude/skills/the-judge/SKILL.md",
	".claude/skills/the-judge/references/comment-voice.md",
	".claude/skills/the-judge/references/review-standards.md",
	".claude/skills/the-judge/scripts/post_review.py",
	".claude/skills/the-judge/scripts/review_gate.py",
	".claude/skills/the-judge/scripts/scan_bypasses.py",
}

// C87 (door 5's caveat, restated in fix round 6): claude-code-action restores
// .claude/ and .mcp.json from the base branch, and Claude Code loads settings,
// hooks, subagents and MCP servers from them, through a symlink as well. So
// git's tracked paths decide: those with a .claude component, at any depth,
// are exactly the-judge's 7 regular files, which leaves nothing beside judge's
// scripts to shadow a module they import, and no path is named .mcp.json.
func TestReviewWorkflow_CheckoutCarriesNoClaudeConfig(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "-s", "-z")
	cmd.Dir = repoRoot(t)
	res := run(t, cmd)
	require.Zero(t, res.code, "git ls-files: %s", res.stderr)

	var tracked, claude, mcp []string
	for _, entry := range strings.Split(strings.TrimSuffix(res.stdout, "\x00"), "\x00") {
		// <mode> SP <object> SP <stage> TAB <path>
		info, p, ok := strings.Cut(entry, "\t")
		require.True(t, ok, "git ls-files -s entry %q has no path", entry)
		tracked = append(tracked, p)
		if slices.Contains(strings.Split(p, "/"), ".claude") {
			mode, _, _ := strings.Cut(info, " ")
			claude = append(claude, mode+" "+p)
		}
		if path.Base(p) == ".mcp.json" {
			mcp = append(mcp, p)
		}
	}
	require.Contains(t, tracked, ".github/workflows/review.yml", "git ls-files did not list this repository")

	want := make([]string, 0, len(judgeSkillFiles))
	for _, p := range judgeSkillFiles {
		want = append(want, "100644 "+p)
	}
	assert.ElementsMatch(t, want, claude, "tracked paths with a .claude component, as <mode> <path>")
	assert.Empty(t, mcp, "tracked paths named .mcp.json")
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// C81 (AC 68): judge fails, leaving nothing to post, when ci-ok never concludes.
func TestReviewWorkflow_JudgeFailsWhenCiOkNeverConcludes(t *testing.T) {
	var gather step
	for _, s := range repoWorkflow(t, "review.yml").job(t, "judge").Steps {
		if s.Name == "Wait for ci-ok and gather the review inputs" {
			gather = s
		}
	}
	require.NotEmpty(t, gather.Run, "judge has no wait-and-gather step")

	// The fake applies the step's --jq to what gh pr checks --json name,bucket
	// prints: every check of the pull request, ci-ok among them once it exists.
	// With --json, gh exits 0 whatever the checks' state; with no check at all
	// it exits 1.
	cases := []struct {
		name   string
		checks ghResponse
	}{
		{"pending", ghResponse{Stdout: `[{"name":"lint","bucket":"pass"},{"name":"ci-ok","bucket":"pending"}]`}},
		{"absent", ghResponse{Stdout: `[{"name":"lint","bucket":"pending"},{"name":"judge","bucket":"pending"}]`}},
		{"absent, no check reported yet", ghResponse{Stderr: "no checks reported on the 'feat/x' branch\n", Exit: 1}},
		{"pass", ghResponse{Stdout: `[{"name":"lint","bucket":"pass"},{"name":"ci-ok","bucket":"pass"},{"name":"judge","bucket":"pending"}]`}},
		{"fail", ghResponse{Stdout: `[{"name":"lint","bucket":"fail"},{"name":"ci-ok","bucket":"fail"},{"name":"judge","bucket":"pending"}]`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Symlink(repoPath(t, ".claude"), filepath.Join(dir, ".claude")))
			gh := newFakeGH(t, map[string]ghResponse{
				"pr checks 7 --json": tc.checks,
				"pr checks 7":        {Stdout: "ci-ok\t" + tc.name + "\n"},
				"pr view 7":          {Stdout: `{"number":7}`},
				"pr diff 7":          {Stdout: "diff --git a/x b/x\n"},
				"GET repos/" + testRepo + "/pulls/7/reviews": {Stdout: "[[]]"},
			})
			r := runStepIn(t, dir, gather.Run, gh.env("PR=7", "GITHUB_REPOSITORY="+testRepo, "GH_REPO="+testRepo,
				"CI_OK_WAIT_ATTEMPTS=2", "CI_OK_WAIT_SECONDS=0"))

			concluded := tc.name == "pass" || tc.name == "fail"
			if concluded {
				require.Equal(t, 0, r.code, r.output())
				assert.FileExists(t, filepath.Join(dir, ".judge", "pr.json"))
				return
			}
			assert.Equal(t, 1, r.code, r.output())
			assert.Regexp(t, `(?m)^::error::.*ci-ok`, r.stdout)
			assert.NoFileExists(t, filepath.Join(dir, ".judge", "pr.json"))
			for _, c := range gh.calls() {
				assert.True(t, strings.HasPrefix(c.Key, "pr checks 7 --json"), "gathered review input anyway: %s", c.Key)
			}
			assert.Len(t, gh.calls(), 2, "the overridden attempt count")
		})
	}
}
