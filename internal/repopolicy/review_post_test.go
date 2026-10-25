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

// review-post.yml posts the review judge wrote, from main's definition and
// scripts only (door 5, amended 2026-10-25).

func reviewPost(t *testing.T) workflowFile {
	t.Helper()
	return repoWorkflow(t, "review-post.yml")
}

func postJob(t *testing.T) job {
	t.Helper()
	return reviewPost(t).job(t, "post")
}

// postStep returns the post job's step with the given name and its index.
func postStep(t *testing.T, name string) (int, step) {
	t.Helper()
	for i, s := range postJob(t).Steps {
		if s.Name == name {
			return i, s
		}
	}
	require.Failf(t, "post step missing", "%q", name)
	return -1, step{}
}

// envVarHolding returns the name of the step env variable whose value is expr.
func envVarHolding(t *testing.T, s step, expr string) string {
	t.Helper()
	for k, v := range s.Env {
		if strings.ReplaceAll(v, " ", "") == strings.ReplaceAll(expr, " ", "") {
			return k
		}
	}
	require.Failf(t, "no env variable", "step %q passes no variable holding %s", s.Name, expr)
	return ""
}

func githubOutput(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "github_output")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	return path
}

func readOutput(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- the temp output file this test created
	require.NoError(t, err)
	return nonEmptyLines(string(b))
}

// C75 (AC 19 amended, AC 69, door 5)
func TestReviewPost_TriggersOnlyOnReviewCompletion(t *testing.T) {
	f := reviewPost(t)
	on := triggers(f.wf)
	assert.Equal(t, []string{"workflow_run"}, keys(on))
	cfg, ok := on["workflow_run"].(map[string]any)
	require.True(t, ok, "workflow_run has no configuration")
	assert.Equal(t, []any{"review"}, cfg["workflows"])
	assert.Equal(t, []any{"completed"}, cfg["types"])
	assert.Equal(t, "review", repoWorkflow(t, "review.yml").wf.Name, "workflows: [review] names review.yml by its name")

	assert.Regexp(t, `(?m)^\s*workflow_run:\s*# zizmor: ignore\[dangerous-triggers\]\s+\S`, string(f.raw),
		"the trigger line must carry the dangerous-triggers ignore followed by its reason")

	for _, w := range repoWorkflows(t) {
		wt := triggers(w.wf)
		_, prt := wt["pull_request_target"]
		assert.False(t, prt, "%s triggers on pull_request_target", w.name)
		if w.name != "review-post.yml" {
			_, wr := wt["workflow_run"]
			assert.False(t, wr, "%s triggers on workflow_run", w.name)
		}
	}
}

// C76 (AC 21 amended, AC 37 amended, door 5)
func TestReviewPost_PostRunsOnlyAfterASuccessfulReview(t *testing.T) {
	f := reviewPost(t)
	assert.Equal(t, map[string]any{}, f.wf.Permissions, "top-level permissions must be {}")
	assert.Equal(t, []string{"post"}, f.jobNames())

	post := postJob(t)
	assert.Equal(t, "review-bot", environmentName(post.Environment))
	assert.Equal(t, map[string]any{"actions": "read", "contents": "read"}, post.Permissions)
	assert.Equal(t, postCondition, normalizeSpace(post.If))
}

// C77 (AC 69, door 5)
func TestReviewPost_ChecksOutNoPullRequestRef(t *testing.T) {
	f := reviewPost(t)
	checkouts := 0
	for _, s := range postJob(t).Steps {
		if !strings.HasPrefix(s.Uses, "actions/checkout@") {
			continue
		}
		checkouts++
		assert.NotContains(t, s.With, "ref", "checkout must take the workflow_run's own commit on main")
		assert.NotContains(t, s.With, "repository")
		for k, v := range s.With {
			assert.NotRegexp(t, `head_sha|head_branch|refs/pull`, v, "checkout input %s", k)
		}
	}
	assert.Equal(t, 1, checkouts)
	assert.NotContains(t, string(f.raw), "refs/pull")
}

const prStepName = "Find the pull request of the reviewed commit"

// postCondition is door 5's literal if: for the post job.
const postCondition = "github.event.workflow_run.conclusion == 'success' && " +
	"(github.event.workflow_run.event == 'pull_request' || github.event.workflow_run.event == 'workflow_dispatch')"

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// C78 (AC 70, door 5): over the accepted case and each of the 4 refusals.
func TestReviewPost_TakesThePullRequestFromTheHeadCommit(t *testing.T) {
	_, s := postStep(t, prStepName)
	require.NotEmpty(t, s.ID)
	assert.NotContains(t, s.Run, "findings", "the number must not come from the artifact")
	shaVar := envVarHolding(t, s, "${{ github.event.workflow_run.head_sha }}")

	const sha = "0123456789abcdef0123456789abcdef01234567"
	pull := func(n int, state, headSHA, headRepo string) string {
		return `{"number":` + strconv.Itoa(n) + `,"state":"` + state + `","head":{"sha":"` + headSHA + `","repo":{"full_name":"` + headRepo + `"}}}`
	}
	cases := []struct {
		name, pulls string
		want        string
	}{
		{"one open pull request from this repository", "[" + pull(7, "open", sha, testRepo) + "]", "7"},
		{"none", "[]", ""},
		{"two", "[" + pull(7, "open", sha, testRepo) + "," + pull(8, "open", sha, testRepo) + "]", ""},
		{"a fork head", "[" + pull(7, "open", sha, "someone/GO-eBPF-Proxy") + "]", ""},
		{"a head.sha mismatch", "[" + pull(7, "open", "fedcba9876543210fedcba9876543210fedcba98", testRepo) + "]", ""},
		{"only the merged pull request", "[" + pull(6, "closed", sha, testRepo) + "]", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh := newFakeGH(t, map[string]ghResponse{"GET repos/" + testRepo + "/commits/" + sha + "/pulls": {Stdout: tc.pulls}})
			out := githubOutput(t)
			r := runStep(t, s.Run, gh.env(shaVar+"="+sha, "GITHUB_REPOSITORY="+testRepo, "GITHUB_OUTPUT="+out, "RUNNER_TEMP="+t.TempDir()))
			require.Equal(t, 0, r.code, r.output())
			if tc.want != "" {
				assert.Equal(t, []string{"number=" + tc.want}, readOutput(t, out))
			} else {
				assert.Empty(t, readOutput(t, out), "no pull request number may be output")
			}
			assert.Equal(t, []string{"GET repos/" + testRepo + "/commits/" + sha + "/pulls"}, callKeys(gh.calls()))
		})
	}

	// Every step after it waits on the number, so nothing is posted without one.
	post := postJob(t)
	idx, _ := postStep(t, prStepName)
	gate := "steps." + s.ID + ".outputs.number != ''"
	for _, later := range post.Steps[idx+1:] {
		assert.Contains(t, later.If, gate, "step %q does not wait on the pull request number", later.Name)
	}
	_, poster := postStep(t, "Post the review as the bot")
	assert.Equal(t, "${{ steps."+s.ID+".outputs.number }}", poster.Env["PR"])
}

const artifactStepName = "Check that the review run left findings"

// C79 (AC 33 amended, door 5)
func TestReviewPost_DownloadsFindingsFromTheTriggeringRunOrPostsNothing(t *testing.T) {
	download, ok := stepUsing(postJob(t), "actions/download-artifact@")
	require.True(t, ok, "post does not download the findings artifact")
	assert.Equal(t, "findings", download.With["name"])
	assert.Equal(t, "${{ github.event.workflow_run.id }}", download.With["run-id"])
	assert.Equal(t, "${{ github.repository }}", download.With["repository"])
	assert.Equal(t, "${{ github.token }}", download.With["github-token"])

	idx, check := postStep(t, artifactStepName)
	assert.Equal(t, 0, idx, "the artifact check runs first")
	require.NotEmpty(t, check.ID)
	runVar := envVarHolding(t, check, "${{ github.event.workflow_run.id }}")
	_, prStep := postStep(t, prStepName)
	assert.Contains(t, prStep.If, "steps."+check.ID+".outputs.found == 'true'")

	cases := []struct {
		name, artifacts, want string
	}{
		{"findings present", `{"total_count":1,"artifacts":[{"name":"findings","expired":false}]}`, "found=true"},
		{"no artifact (the guard skipped the pull request)", `{"total_count":0,"artifacts":[]}`, "found=false"},
		{"findings expired", `{"total_count":1,"artifacts":[{"name":"findings","expired":true}]}`, "found=false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gh := newFakeGH(t, map[string]ghResponse{"GET repos/" + testRepo + "/actions/runs/123/artifacts": {Stdout: tc.artifacts}})
			out := githubOutput(t)
			r := runStep(t, check.Run, gh.env(runVar+"=123", "GITHUB_REPOSITORY="+testRepo, "GITHUB_OUTPUT="+out, "RUNNER_TEMP="+t.TempDir()))
			require.Equal(t, 0, r.code, r.output())
			assert.Equal(t, []string{tc.want}, readOutput(t, out))
		})
	}
}

// C45 (AC 36, door 5)
func TestReviewPost_PostRunsNoClaudeStep(t *testing.T) {
	post := postJob(t)
	require.NotEmpty(t, post.Steps)
	_, ok := stepUsing(post, "anthropics/claude-code-action@")
	assert.False(t, ok)
}

// C46 (AC 37, amended 2026-10-25)
func TestReviewPost_PostRunsOnlyWhenTheReviewSucceeded(t *testing.T) {
	post := postJob(t)
	assert.Equal(t, postCondition, normalizeSpace(post.If), "the condition must require a successful review run")
	for _, fn := range []string{"always()", "failure()", "cancelled()"} {
		assert.NotContains(t, post.If, fn)
	}
}

// C55 (door 4): the App token asks for exactly Contents read and Pull requests
// write; Metadata read comes with every installation token.
func TestReviewPost_TokenRequestsOnlyContentsReadAndPullRequestsWrite(t *testing.T) {
	mint, ok := stepUsing(postJob(t), "actions/create-github-app-token@")
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
func TestReviewPost_AssertsTheBotIsInstalledOnThisRepositoryOnly(t *testing.T) {
	idx, confirm := postStep(t, "Confirm the bot is installed on this repository only")
	post := postJob(t)
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
