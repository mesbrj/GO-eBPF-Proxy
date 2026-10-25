package repopolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// C42 (AC 33): over each of the 3 conditions, on both paths.
func TestReviewWorkflow_SkipsDraftDependabotAndForkPullRequests(t *testing.T) {
	review := repoWorkflow(t, "review.yml")
	judge, post := review.job(t, "judge"), review.job(t, "post")

	conditions := map[string]string{
		"draft":           "!github.event.pull_request.draft",
		"dependabot[bot]": "github.event.pull_request.user.login != 'dependabot[bot]'",
		"fork head":       "github.event.pull_request.head.repo.full_name == github.repository",
	}
	for name, cond := range conditions {
		assert.Contains(t, judge.If, cond, "judge's if: lacks the %s condition", name)
		assert.Contains(t, post.If, cond, "post's if: lacks the %s condition", name)
	}

	// The dispatch path: the guard step decides, and every later judge step and
	// the post job wait on its output.
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
	assert.Equal(t, "${{ steps."+guard.ID+".outputs.eligible }}", judge.Outputs["eligible"])
	assert.Contains(t, post.If, "needs.judge.outputs.eligible == 'true'")

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

// claudeStep returns judge's claude-code-action step.
func claudeStep(t *testing.T) step {
	t.Helper()
	s, ok := stepUsing(repoWorkflow(t, "review.yml").job(t, "judge"), "anthropics/claude-code-action@")
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

// allowedTools collects every rule passed with --allowedTools (or
// --allowed-tools) in claude_args. Rules are separated by commas or spaces
// outside parentheses.
func allowedTools(args string) []string {
	flagRE := regexp.MustCompile(`--allowed(?:Tools|-tools)(?:=|\s+)("[^"]*"|'[^']*'|\S+)`)
	var rules []string
	for _, m := range flagRE.FindAllStringSubmatch(args, -1) {
		v := strings.Trim(m[1], `"'`)
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
			case (r == ',' || r == ' ') && depth == 0:
				flush()
				continue
			}
			cur.WriteRune(r)
		}
		flush()
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

// C45 (AC 36, door 5)
func TestReviewWorkflow_PostJobRunsNoClaudeStep(t *testing.T) {
	post := repoWorkflow(t, "review.yml").job(t, "post")
	require.NotEmpty(t, post.Steps)
	_, ok := stepUsing(post, "anthropics/claude-code-action@")
	assert.False(t, ok)
}

// C46 (AC 37)
func TestReviewWorkflow_PostNeedsJudgeWithoutAlwaysCondition(t *testing.T) {
	post := repoWorkflow(t, "review.yml").job(t, "post")
	assert.Contains(t, []string(post.Needs), "judge")
	for _, fn := range []string{"always()", "failure()", "cancelled()"} {
		assert.NotContains(t, post.If, fn)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// postStep returns the post job's step with the given name.
func postStep(t *testing.T, name string) (int, step) {
	t.Helper()
	post := repoWorkflow(t, "review.yml").job(t, "post")
	for i, s := range post.Steps {
		if s.Name == name {
			return i, s
		}
	}
	require.Failf(t, "post step missing", "%q", name)
	return -1, step{}
}

// C55 (door 4): the App token asks for exactly Contents read and Pull requests
// write; Metadata read comes with every installation token.
func TestReviewWorkflow_PostTokenRequestsOnlyContentsReadAndPullRequestsWrite(t *testing.T) {
	mint, ok := stepUsing(repoWorkflow(t, "review.yml").job(t, "post"), "actions/create-github-app-token@")
	require.True(t, ok, "post does not mint an App token")
	perms := map[string]any{}
	for k, v := range mint.With {
		if strings.HasPrefix(k, "permission-") {
			perms[k] = v
		}
	}
	assert.Equal(t, map[string]any{"permission-contents": "read", "permission-pull-requests": "write"}, perms)
}

// C55 (door 4): before posting, post checks with the App token that the bot is
// installed on this repository alone, and fails otherwise.
func TestReviewWorkflow_PostAssertsTheBotIsInstalledOnThisRepositoryOnly(t *testing.T) {
	const name = "Confirm the bot is installed on this repository only"
	idx, confirm := postStep(t, name)
	post := repoWorkflow(t, "review.yml").job(t, "post")
	mintIdx := -1
	for i, s := range post.Steps {
		if strings.HasPrefix(s.Uses, "actions/create-github-app-token@") {
			mintIdx = i
		}
	}
	postIdx := stepIndex(post, regexp.MustCompile(`post_review\.py`))
	assert.Greater(t, idx, mintIdx, "the check needs the App token")
	assert.Less(t, idx, postIdx, "the check must run before anything is posted")
	assert.Equal(t, "${{ steps.app-token.outputs.token }}", confirm.Env["GH_TOKEN"])

	installation := func(selection string, repos ...string) string {
		var list []string
		for _, r := range repos {
			list = append(list, `{"full_name":"`+r+`"}`)
		}
		return `{"total_count":` + strconv.Itoa(len(repos)) + `,"repository_selection":"` + selection + `","repositories":[` + strings.Join(list, ",") + `]}`
	}
	cases := []struct {
		name, response string
		ok             bool
	}{
		{"selected, this repository only", installation("selected", testRepo), true},
		{"installed on all repositories", installation("all", testRepo), false},
		{"selected, another repository too", installation("selected", testRepo, "mesbrj/other"), false},
		{"selected, another repository only", installation("selected", "mesbrj/other"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh := newFakeGH(t, map[string]ghResponse{"GET installation/repositories": {Stdout: tc.response}})
			r := runStep(t, confirm.Run, gh.env("GITHUB_REPOSITORY="+testRepo, "RUNNER_TEMP="+t.TempDir()))
			if tc.ok {
				require.Equal(t, 0, r.code, r.output())
				assert.Contains(t, nonEmptyLines(r.stdout), "installation repository_selection: selected")
				assert.Contains(t, nonEmptyLines(r.stdout), "installation repositories: "+testRepo)
			} else {
				assert.NotEqual(t, 0, r.code, r.output())
			}
			assert.Equal(t, []string{"GET installation/repositories"}, callKeys(gh.calls()), "one read, no write")
		})
	}
}
