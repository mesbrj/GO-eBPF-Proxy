package repopolicy

import (
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const policyAPI = "repos/" + testRepo

// policySettings are the 12 settings repo-policy.sh compares (AC 62, amended
// 2026-10-25), by the name each one's output line carries.
var policySettings = []string{
	"ruleset",
	"allow_merge_commit",
	"allow_rebase_merge",
	"allow_squash_merge",
	"pull_request_creation_policy",
	"fork_pr_approval_policy",
	"default_workflow_permissions",
	"can_approve_pull_request_reviews",
	"sha_pinning_required",
	"vulnerability_alerts",
	"automated_security_fixes",
	"review_bot_deployment_branches",
}

const liveRulesetID = "42"

// liveRuleset is main.json as GitHub returns it: with the fields the server
// assigns, keys in another order.
func liveRuleset(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	var r map[string]any
	require.NoError(t, json.Unmarshal(readRepoFile(t, ".github/rulesets/main.json"), &r))
	r["id"] = 42
	r["node_id"] = "RRS_lACqUmVwb3NpdG9yec4AAAAA"
	r["source"] = testRepo
	r["source_type"] = "Repository"
	r["created_at"] = "2026-10-25T10:00:00.000-03:00"
	r["updated_at"] = "2026-10-25T10:00:00.000-03:00"
	r["current_user_can_bypass"] = "never"
	r["_links"] = map[string]any{"self": map[string]string{"href": "https://api.github.com/" + policyAPI + "/rulesets/42"}}
	if edit != nil {
		edit(r)
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	return string(b)
}

func rulesetName(t *testing.T) string {
	t.Helper()
	return mainRuleset(t).Name
}

// compliantRepo answers every read check makes with the committed policy in force.
func compliantRepo(t *testing.T) map[string]ghResponse {
	t.Helper()
	return map[string]ghResponse{
		"GET " + policyAPI:                                                         {Stdout: `{"name":"GO-eBPF-Proxy","allow_merge_commit":false,"allow_rebase_merge":true,"allow_squash_merge":true,"pull_request_creation_policy":"collaborators_only","visibility":"public"}`},
		"GET " + policyAPI + "/actions/permissions":                                {Stdout: `{"enabled":true,"allowed_actions":"all","sha_pinning_required":true}`},
		"GET " + policyAPI + "/actions/permissions/workflow":                       {Stdout: `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}`},
		"GET " + policyAPI + "/actions/permissions/fork-pr-contributor-approval":   {Stdout: `{"approval_policy":"all_external_contributors"}`},
		"GET " + policyAPI + "/vulnerability-alerts":                               {},
		"GET " + policyAPI + "/automated-security-fixes":                           {Stdout: `{"enabled":true,"paused":false}`},
		"GET " + policyAPI + "/rulesets":                                           {Stdout: `[{"id":42,"name":"` + rulesetName(t) + `","target":"branch","source_type":"Repository","source":"` + testRepo + `","enforcement":"active"}]`},
		"GET " + policyAPI + "/rulesets/" + liveRulesetID:                          {Stdout: liveRuleset(t, nil)},
		"GET " + policyAPI + "/environments/review-bot":                            {Stdout: `{"name":"review-bot","deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`},
		"GET " + policyAPI + "/environments/review-bot/deployment-branch-policies": {Stdout: `{"total_count":1,"branch_policies":[{"id":1,"node_id":"MDE2","name":"main","type":"branch"}]}`},
	}
}

// driftedRepo is compliantRepo with exactly the named setting off-policy.
func driftedRepo(t *testing.T, setting string) map[string]ghResponse {
	t.Helper()
	r := compliantRepo(t)
	repo := func(field, value string) {
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(r["GET "+policyAPI].Stdout), &m))
		m[field] = json.RawMessage(value)
		b, err := json.Marshal(m)
		require.NoError(t, err)
		r["GET "+policyAPI] = ghResponse{Stdout: string(b)}
	}
	switch setting {
	case "ruleset":
		r["GET "+policyAPI+"/rulesets/"+liveRulesetID] = ghResponse{Stdout: liveRuleset(t, func(m map[string]any) {
			m["bypass_actors"] = []any{map[string]any{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}}
		})}
	case "allow_merge_commit":
		repo("allow_merge_commit", "true")
	case "allow_rebase_merge":
		repo("allow_rebase_merge", "false")
	case "allow_squash_merge":
		repo("allow_squash_merge", "false")
	case "pull_request_creation_policy":
		repo("pull_request_creation_policy", `"all"`)
	case "fork_pr_approval_policy":
		r["GET "+policyAPI+"/actions/permissions/fork-pr-contributor-approval"] = ghResponse{Stdout: `{"approval_policy":"first_time_contributors"}`}
	case "default_workflow_permissions":
		r["GET "+policyAPI+"/actions/permissions/workflow"] = ghResponse{Stdout: `{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`}
	case "can_approve_pull_request_reviews":
		r["GET "+policyAPI+"/actions/permissions/workflow"] = ghResponse{Stdout: `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}`}
	case "sha_pinning_required":
		r["GET "+policyAPI+"/actions/permissions"] = ghResponse{Stdout: `{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}`}
	case "vulnerability_alerts":
		r["GET "+policyAPI+"/vulnerability-alerts"] = ghResponse{Stderr: "gh: Vulnerability alerts are disabled. (HTTP 404)\n", Exit: 1}
	case "automated_security_fixes":
		r["GET "+policyAPI+"/automated-security-fixes"] = ghResponse{Stdout: `{"enabled":false,"paused":false}`}
	case "review_bot_deployment_branches":
		r["GET "+policyAPI+"/environments/review-bot"] = ghResponse{Stdout: `{"name":"review-bot","deployment_branch_policy":null}`}
	default:
		require.Failf(t, "unknown setting", "%s", setting)
	}
	return r
}

func repoPolicy(t *testing.T, gh *fakeGH, args ...string) result {
	t.Helper()
	cmd := exec.Command(repoPath(t, "deploy/github/repo-policy.sh"), args...) // #nosec G204 -- the script under test with fixed arguments
	cmd.Env = gh.env()
	return run(t, cmd)
}

// C61 (AC 62): over each of the 12 settings.
func TestRepoPolicy_CheckExitsOneNamingEachDifferingSetting(t *testing.T) {
	require.Len(t, policySettings, 12)
	for _, setting := range policySettings {
		t.Run(setting, func(t *testing.T) {
			gh := newFakeGH(t, driftedRepo(t, setting))
			r := repoPolicy(t, gh, "check")
			assert.Equal(t, 1, r.code, r.output())

			var wants []string
			for _, l := range nonEmptyLines(r.stdout) {
				if strings.HasPrefix(l, "want ") {
					wants = append(wants, l)
				}
			}
			require.Len(t, wants, 1, "exactly one setting differs:\n%s", r.stdout)
			assert.Contains(t, wants[0], " got ")
			assert.Regexp(t, `\b`+setting+`\b`, wants[0])
			for _, other := range policySettings {
				if other != setting {
					assert.Contains(t, nonEmptyLines(r.stdout), "ok "+other)
				}
			}
		})
	}
}

// C62 (AC 62)
func TestRepoPolicy_CheckExitsZeroWhenEverySettingMatches(t *testing.T) {
	gh := newFakeGH(t, compliantRepo(t))
	r := repoPolicy(t, gh, "check")
	assert.Equal(t, 0, r.code, r.output())

	var want []string
	for _, s := range policySettings {
		want = append(want, "ok "+s)
	}
	assert.ElementsMatch(t, want, nonEmptyLines(r.stdout))
	for _, c := range gh.calls() {
		assert.True(t, strings.HasPrefix(c.Key, "GET "), "check made a write: %s", c.Key)
	}
}

// writeKey identifies a write by method, path and the setting fields it sends;
// enabled is the endpoint's required companion of sha_pinning_required.
func writeKey(c ghCall) string {
	fields := apiFields(c.Args)
	delete(fields, "enabled")
	var kv []string
	for k, v := range fields {
		kv = append(kv, k+"="+v)
	}
	sort.Strings(kv)
	return strings.TrimSpace(c.Key + " " + strings.Join(kv, " "))
}

// C63 (AC 63): one write per setting for each of the 12, then check's reads,
// exiting with check's code; an existing ruleset is updated by id, never duplicated.
func TestRepoPolicy_ApplyWritesEverySettingThenChecks(t *testing.T) {
	wantWrites := []string{
		"PATCH " + policyAPI + " allow_merge_commit=false",
		"PATCH " + policyAPI + " allow_rebase_merge=true",
		"PATCH " + policyAPI + " allow_squash_merge=true",
		"PATCH " + policyAPI + " pull_request_creation_policy=collaborators_only",
		"PUT " + policyAPI + "/actions/permissions/fork-pr-contributor-approval approval_policy=all_external_contributors",
		"PUT " + policyAPI + "/actions/permissions/workflow default_workflow_permissions=read",
		"PUT " + policyAPI + "/actions/permissions/workflow can_approve_pull_request_reviews=false",
		"PUT " + policyAPI + "/actions/permissions sha_pinning_required=true",
		"PUT " + policyAPI + "/vulnerability-alerts",
		"PUT " + policyAPI + "/automated-security-fixes",
		"PUT " + policyAPI + "/rulesets/" + liveRulesetID,
		"PUT " + policyAPI + "/environments/review-bot deployment_branch_policy[custom_branch_policies]=true deployment_branch_policy[protected_branches]=false",
	}
	require.Len(t, wantWrites, len(policySettings))

	for _, tc := range []struct {
		name  string
		state func(t *testing.T) map[string]ghResponse
	}{
		{"compliant after the writes", compliantRepo},
		{"still drifted after the writes", func(t *testing.T) map[string]ghResponse { return driftedRepo(t, "allow_merge_commit") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gh := newFakeGH(t, tc.state(t))
			check := repoPolicy(t, gh, "check")
			checkReads := callKeys(gh.calls())

			gh.respond(tc.state(t))
			apply := repoPolicy(t, gh, "apply")
			calls := gh.calls()

			assert.Equal(t, check.code, apply.code, "apply must exit with check's code\n%s", apply.output())
			assert.Equal(t, check.stdout, apply.stdout, "apply must finish with check's comparison")

			last := -1
			var writes []string
			for i, c := range calls {
				if !strings.HasPrefix(c.Key, "GET ") {
					writes = append(writes, writeKey(c))
					last = i
					if c.Key == "PUT "+policyAPI+"/rulesets/"+liveRulesetID {
						assert.JSONEq(t, string(readRepoFile(t, ".github/rulesets/main.json")), c.Input, "the ruleset write must send main.json")
					}
				}
			}
			assert.ElementsMatch(t, wantWrites, writes)
			assert.NotContains(t, callKeys(calls), "POST "+policyAPI+"/rulesets", "an existing ruleset must not be duplicated")
			require.GreaterOrEqual(t, last, 0)
			assert.Equal(t, checkReads, callKeys(calls[last+1:]), "after its writes apply must make check's reads")
		})
	}
}

// C80 (AC 71, door 11): apply creates review-bot's main deployment branch
// policy only when it is absent, so a second apply creates nothing.
func TestRepoPolicy_ApplyCreatesTheMainBranchPolicyOnlyWhenAbsent(t *testing.T) {
	const create = "POST " + policyAPI + "/environments/review-bot/deployment-branch-policies"
	for _, tc := range []struct {
		name     string
		policies string
		creates  int
	}{
		{"absent", `{"total_count":0,"branch_policies":[]}`, 1},
		{"present", `{"total_count":1,"branch_policies":[{"id":1,"node_id":"MDE2","name":"main","type":"branch"}]}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := compliantRepo(t)
			state["GET "+policyAPI+"/environments/review-bot/deployment-branch-policies"] = ghResponse{Stdout: tc.policies}
			gh := newFakeGH(t, state)
			repoPolicy(t, gh, "apply")
			var creates []ghCall
			for _, c := range gh.calls() {
				if c.Key == create {
					creates = append(creates, c)
				}
			}
			require.Len(t, creates, tc.creates)
			for _, c := range creates {
				assert.Equal(t, map[string]string{"name": "main", "type": "branch"}, apiFields(c.Args))
			}
		})
	}
}

// C64 (AC 64)
func TestRepoPolicy_UsageExitsTwo(t *testing.T) {
	for name, args := range map[string][]string{"no argument": nil, "status": {"status"}} {
		t.Run(name, func(t *testing.T) {
			gh := newFakeGH(t, nil)
			r := repoPolicy(t, gh, args...)
			assert.Equal(t, 2, r.code, r.output())
			assert.Contains(t, strings.ToLower(r.output()), "usage")
			assert.Contains(t, r.output(), "check")
			assert.Contains(t, r.output(), "apply")
			assert.Empty(t, gh.calls(), "usage must not touch GitHub")
		})
	}
}
