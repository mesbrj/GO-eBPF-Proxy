package repopolicy

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// --- Dependabot -----------------------------------------------------------

type dependabotGroup struct {
	Patterns        []string `yaml:"patterns"`
	ExcludePatterns []string `yaml:"exclude-patterns"`
	UpdateTypes     []string `yaml:"update-types"`
}

type dependabotUpdate struct {
	Ecosystem string `yaml:"package-ecosystem"`
	Directory string `yaml:"directory"`
	Schedule  struct {
		Interval string `yaml:"interval"`
	} `yaml:"schedule"`
	Cooldown struct {
		DefaultDays int `yaml:"default-days"`
	} `yaml:"cooldown"`
	Groups map[string]dependabotGroup `yaml:"groups"`
}

type dependabotConfig struct {
	Version int                `yaml:"version"`
	Updates []dependabotUpdate `yaml:"updates"`
}

func dependabot(t *testing.T) dependabotConfig {
	t.Helper()
	var c dependabotConfig
	require.NoError(t, yaml.Unmarshal(readRepoFile(t, ".github/dependabot.yml"), &c))
	return c
}

func dependabotEntry(t *testing.T, ecosystem string) dependabotUpdate {
	t.Helper()
	for _, u := range dependabot(t).Updates {
		if u.Ecosystem == ecosystem {
			return u
		}
	}
	require.Failf(t, "no Dependabot entry", "%s", ecosystem)
	return dependabotUpdate{}
}

// globMatch matches a Dependabot dependency pattern, where * spans any run of characters.
func globMatch(pattern, name string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	return regexp.MustCompile(re).MatchString(name)
}

func groupMatches(g dependabotGroup, dep string) bool {
	for _, ex := range g.ExcludePatterns {
		if globMatch(ex, dep) {
			return false
		}
	}
	for _, p := range g.Patterns {
		if globMatch(p, dep) {
			return true
		}
	}
	return false
}

// C56 (AC 46)
func TestDependabot_DeclaresActionsAndGomodWeeklyWithSevenDayCooldown(t *testing.T) {
	c := dependabot(t)
	assert.Equal(t, 2, c.Version)
	require.Len(t, c.Updates, 2)
	var ecosystems []string
	for _, u := range c.Updates {
		ecosystems = append(ecosystems, u.Ecosystem)
		assert.Equal(t, "/", u.Directory, u.Ecosystem)
		assert.Equal(t, "weekly", u.Schedule.Interval, u.Ecosystem)
		assert.Equal(t, 7, u.Cooldown.DefaultDays, u.Ecosystem)
	}
	assert.ElementsMatch(t, []string{"github-actions", "gomod"}, ecosystems)
}

// C57 (AC 47)
func TestDependabot_GroupsEveryActionsUpdate(t *testing.T) {
	groups := dependabotEntry(t, "github-actions").Groups
	require.Len(t, groups, 1)
	for _, g := range groups {
		assert.Equal(t, []string{"*"}, g.Patterns)
		assert.Empty(t, g.ExcludePatterns)
	}
}

// C58 (AC 48)
func TestDependabot_GroupsGomodMinorPatchExceptCiliumEbpf(t *testing.T) {
	groups := dependabotEntry(t, "gomod").Groups
	require.Len(t, groups, 1)
	for name, g := range groups {
		assert.Equal(t, []string{"*"}, g.Patterns, name)
		assert.ElementsMatch(t, []string{"minor", "patch"}, g.UpdateTypes, name)
		assert.Contains(t, g.ExcludePatterns, "github.com/cilium/ebpf", name)
		assert.True(t, groupMatches(g, "github.com/knadh/koanf/v2"), "group %s must take the other modules", name)
	}
	for name, g := range groups {
		assert.False(t, groupMatches(g, "github.com/cilium/ebpf"), "group %s matches github.com/cilium/ebpf", name)
	}
}

// --- Ruleset --------------------------------------------------------------

type rulesetRule struct {
	Type       string         `json:"type"`
	Parameters map[string]any `json:"parameters"`
}

type ruleset struct {
	Name         string `json:"name"`
	Target       string `json:"target"`
	Enforcement  string `json:"enforcement"`
	BypassActors *[]any `json:"bypass_actors"`
	Conditions   struct {
		RefName struct {
			Include []string `json:"include"`
			Exclude []string `json:"exclude"`
		} `json:"ref_name"`
	} `json:"conditions"`
	Rules []rulesetRule `json:"rules"`
}

func mainRuleset(t *testing.T) ruleset {
	t.Helper()
	var r ruleset
	require.NoError(t, json.Unmarshal(readRepoFile(t, ".github/rulesets/main.json"), &r))
	return r
}

func (r ruleset) rule(t *testing.T, typ string) rulesetRule {
	t.Helper()
	for _, rr := range r.Rules {
		if rr.Type == typ {
			return rr
		}
	}
	require.Failf(t, "rule missing", "main.json has no %s rule", typ)
	return rulesetRule{}
}

// C65 (AC 52)
func TestRuleset_HasNoBypassActor(t *testing.T) {
	r := mainRuleset(t)
	require.NotNil(t, r.BypassActors, "bypass_actors must be stated, as []")
	assert.Empty(t, *r.BypassActors)
}

// C66 (AC 53)
func TestRuleset_RequiresPullRequestWithZeroApprovalsAndResolvedThreads(t *testing.T) {
	p := mainRuleset(t).rule(t, "pull_request").Parameters
	assert.Equal(t, float64(0), p["required_approving_review_count"])
	assert.Equal(t, true, p["required_review_thread_resolution"])
}

// C67 (AC 54, door 1)
func TestRuleset_RequiresOnlyCiOkWithStrictPolicy(t *testing.T) {
	p := mainRuleset(t).rule(t, "required_status_checks").Parameters
	assert.Equal(t, true, p["strict_required_status_checks_policy"])
	checks, ok := p["required_status_checks"].([]any)
	require.True(t, ok)
	var contexts []any
	for _, c := range checks {
		m, ok := c.(map[string]any)
		require.True(t, ok)
		contexts = append(contexts, m["context"])
	}
	assert.Equal(t, []any{"ci-ok"}, contexts)
}

// C68 (AC 55, door 7)
func TestRuleset_RequiresLinearHistoryAndBlocksForcePushAndDeletion(t *testing.T) {
	r := mainRuleset(t)
	assert.Equal(t, "branch", r.Target)
	assert.Equal(t, []string{"~DEFAULT_BRANCH"}, r.Conditions.RefName.Include)
	assert.Equal(t, "active", r.Enforcement)
	var types []string
	for _, rr := range r.Rules {
		types = append(types, rr.Type)
	}
	assert.ElementsMatch(t, []string{"deletion", "non_fast_forward", "pull_request", "required_linear_history", "required_status_checks"}, types)
}

// --- CODEOWNERS -----------------------------------------------------------

// C69 (AC 57)
func TestCodeowners_OnlyRuleIsEveryFileToMesbrj(t *testing.T) {
	var rules []string
	for _, l := range strings.Split(string(readRepoFile(t, ".github/CODEOWNERS")), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			rules = append(rules, l)
		}
	}
	assert.Equal(t, []string{"* @mesbrj"}, rules)
}

// --- platform-e2e.yml -----------------------------------------------------

// C72 (AC 65)
func TestPlatformE2E_TriggersOnWorkflowDispatchOnly(t *testing.T) {
	on := triggers(repoWorkflow(t, "platform-e2e.yml").wf)
	assert.Equal(t, []string{"workflow_dispatch"}, keys(on))
	if cfg, ok := on["workflow_dispatch"].(map[string]any); ok {
		assert.Empty(t, cfg["inputs"], "workflow_dispatch takes no inputs")
	} else {
		assert.Nil(t, on["workflow_dispatch"])
	}
}

// C73 (AC 66)
func TestPlatformE2E_JobEmitsErrorNamingFeature04AndExitsOne(t *testing.T) {
	f := repoWorkflow(t, "platform-e2e.yml")
	require.Len(t, f.wf.Jobs, 1)
	j := f.job(t, f.jobNames()[0])
	var script strings.Builder
	for _, s := range j.Steps {
		require.Empty(t, s.Uses, "the lane runs no action")
		script.WriteString(s.Run + "\n")
	}

	r := runStep(t, script.String(), cleanEnv())
	assert.Equal(t, 1, r.code, r.output())
	found := false
	for _, l := range nonEmptyLines(r.stdout) {
		if strings.HasPrefix(l, "::error::") && strings.Contains(l, "Feature 04") {
			found = true
		}
	}
	assert.True(t, found, "no ::error:: line naming Feature 04 in:\n%s", r.stdout)
}

// C74 (AC 67)
func TestPlatformE2E_ReferencesNoSecretEnvironmentOrSelfHosted(t *testing.T) {
	f := repoWorkflow(t, "platform-e2e.yml")
	assert.NotRegexp(t, secretRefRE, string(f.raw))
	assert.NotRegexp(t, `(?m)^\s*environment\s*:`, string(f.raw))
	assert.NotContains(t, string(f.raw), "self-hosted")
	for _, name := range f.jobNames() {
		j := f.wf.Jobs[name]
		assert.Nil(t, j.Environment, name)
		b, err := json.Marshal(j.RunsOn)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "self-hosted", name)
	}
}
