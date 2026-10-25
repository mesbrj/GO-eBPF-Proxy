package repopolicy

import (
	"crypto/sha1" // #nosec G505 -- git blob ids are SHA-1 by definition; nothing here is a security boundary
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const judgeScripts = ".claude/skills/the-judge/scripts"

// upstreamBlobs are the git blob ids of the-judge v1.4.0's scripts as vendored
// in 90cff87 (`git rev-parse 90cff87:.claude/skills/the-judge/scripts/<name>`).
// A squash or rebase merge rewrites that commit, so the bytes are kept under
// testdata and proven identical to it by their blob id.
var upstreamBlobs = map[string]string{ // #nosec G101 -- git blob ids, not credentials
	"post_review.py":   "7b2b9d12bab59de7e77d46f75b01c4eed97f2013",
	"review_gate.py":   "fe04709ad8c406746e11827a3dd81b2d7c0d73f1",
	"scan_bypasses.py": "02c3969a138a14191c7bde303de04949d819adf8",
}

func gitBlobID(b []byte) string {
	h := sha1.New() // #nosec G401 -- git's object id, not a security hash
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(b))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// upstreamDir returns the directory holding upstream v1.4.0's scripts, after
// proving each is byte-identical to 90cff87's.
func upstreamDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", "the-judge-v1.4.0")
	for name, want := range upstreamBlobs {
		b, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a fixture under testdata
		require.NoError(t, err)
		require.Equal(t, want, gitBlobID(b), "%s is not upstream v1.4.0's", name)
	}
	abs, err := filepath.Abs(dir)
	require.NoError(t, err)
	return abs
}

func patchedScript(t *testing.T, name string) string {
	t.Helper()
	return repoPath(t, judgeScripts+"/"+name)
}

// headerComment returns the comment block that opens a Python script, after its shebang.
func headerComment(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a vendored script named by the test
	require.NoError(t, err)
	var lines []string
	for i, l := range strings.Split(string(b), "\n") {
		if i == 0 && strings.HasPrefix(l, "#!") {
			continue
		}
		if !strings.HasPrefix(l, "#") {
			break
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

func assertModificationNotice(t *testing.T, path, change string) {
	t.Helper()
	h := headerComment(t, path)
	assert.Contains(t, h, "the-judge v1.4.0")
	assert.Regexp(t, `\b2026-\d{2}-\d{2}\b`, h)
	assert.Contains(t, h, change, "the notice does not name the change")
}

// --- post_review.py -------------------------------------------------------

const testRepo = "mesbrj/GO-eBPF-Proxy"

// findings returns a findings.json that passes review_gate.py with verdict.
func findings(t *testing.T, verdict string) []byte {
	t.Helper()
	f := map[string]any{
		"language": "en", "round": 1,
		"carryover": map[string]int{"blocker": 0, "should-fix": 0},
		"verdict":   verdict,
		"summary": "## TL;DR\nThe change adds a port parser. Verdict: " + verdict + ".\n\n" +
			"## Findings\n| ID | Severity | Location | Summary |\n|---|---|---|---|\n\n" +
			"## Promote to lint rule\nnone\n\n## Research log\nno external surfaces touched\n\n" +
			"## Checks run\nci-ok pass\n\n## Skipped files\nnone",
	}
	evidence := []map[string]string{{"type": "internal", "ref": "internal/x/x.go:12"}}
	switch verdict {
	case "APPROVE":
		f["findings"] = []map[string]any{{"id": "F1", "path": "internal/x/x.go", "line": 12, "severity": "nit",
			"body": "\U0001F7E1 `parse` repeats the bounds check from line 10 (internal/x/x.go:12)."}}
	case "COMMENT":
		f["findings"] = []map[string]any{{"id": "F1", "path": "internal/x/x.go", "line": 12, "severity": "should-fix",
			"body": "\U0001F7E0 `parse` drops the error from `strconv.Atoi` (internal/x/x.go:12).", "evidence": evidence}}
	case "REQUEST_CHANGES":
		f["findings"] = []map[string]any{{"id": "F1", "path": "internal/x/x.go", "line": 12, "severity": "blocker",
			"body": "\U0001F534 `parse` indexes the slice without a length check (internal/x/x.go:12).", "evidence": evidence}}
	default:
		require.Failf(t, "unknown verdict", "%s", verdict)
	}
	b, err := json.Marshal(f)
	require.NoError(t, err)
	return b
}

// reviewResponses answer post_review.py's gh calls for pull request 7 by author,
// with "mesbrj" as the authenticated gh user.
func reviewResponses(author string) map[string]ghResponse {
	return map[string]ghResponse{
		"pr view":   {Stdout: `{"number":7,"author":{"login":"` + author + `"}}`},
		"repo view": {Stdout: `{"owner":{"login":"mesbrj"},"name":"GO-eBPF-Proxy"}`},
		"GET user":  {Stdout: "mesbrj\n"},
		"POST repos/" + testRepo + "/pulls/7/reviews": {Stdout: `{"html_url":"https://github.com/mesbrj/GO-eBPF-Proxy/pull/7#pullrequestreview-1"}`},
	}
}

func runPostReview(t *testing.T, gh *fakeGH, script string, findingsJSON []byte, extraEnv ...string) result {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "findings.json"), findingsJSON, 0o600))
	cmd := exec.Command("python3", script, "findings.json", "--pr", "7") // #nosec G204 -- a vendored script named by the test
	cmd.Dir = dir
	cmd.Env = gh.env(extraEnv...)
	return run(t, cmd)
}

// submittedReview returns the payload of the one review submission recorded.
func submittedReview(t *testing.T, calls []ghCall) map[string]any {
	t.Helper()
	var posts []ghCall
	for _, c := range calls {
		if c.Key == "POST repos/"+testRepo+"/pulls/7/reviews" {
			posts = append(posts, c)
		}
	}
	require.Len(t, posts, 1, "review submissions")
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(posts[0].Input), &payload))
	return payload
}

// C47 (AC 38)
func TestPostReview_RefusesWhenGateFails(t *testing.T) {
	bad := findings(t, "REQUEST_CHANGES")
	var f map[string]any
	require.NoError(t, json.Unmarshal(bad, &f))
	f["verdict"] = "APPROVE" // a blocker with an APPROVE verdict fails the gate
	bad, err := json.Marshal(f)
	require.NoError(t, err)

	for name, env := range map[string][]string{"bot mode": {"JUDGE_BOT_LOGIN=review-bot[bot]"}, "upstream mode": nil} {
		t.Run(name, func(t *testing.T) {
			gh := newFakeGH(t, reviewResponses("mesbrj"))
			r := runPostReview(t, gh, patchedScript(t, "post_review.py"), bad, env...)
			assert.Equal(t, 1, r.code, r.output())
			assert.Contains(t, r.output(), "refusing to post")
			for _, c := range gh.calls() {
				assert.NotContains(t, c.Key, "/pulls/7/reviews", "a review call was made")
			}
		})
	}
}

// C48 (AC 39, door 6): over each of the 3 verdicts.
func TestPostReview_BotModePostsCommentForEveryVerdict(t *testing.T) {
	for _, verdict := range []string{"APPROVE", "COMMENT", "REQUEST_CHANGES"} {
		t.Run(verdict, func(t *testing.T) {
			gh := newFakeGH(t, reviewResponses("mesbrj"))
			r := runPostReview(t, gh, patchedScript(t, "post_review.py"), findings(t, verdict), "JUDGE_BOT_LOGIN=review-bot[bot]")
			require.Equal(t, 0, r.code, r.output())

			calls := gh.calls()
			for _, c := range calls {
				assert.NotEqual(t, "GET user", c.Key, "bot mode called gh api user")
			}
			assert.Equal(t, "COMMENT", submittedReview(t, calls)["event"])
			assert.Contains(t, r.stdout, "posted: event=COMMENT")
		})
	}
}

// C49 (AC 40)
func TestPostReview_BotModeAppendsIntendedVerdict(t *testing.T) {
	for _, verdict := range []string{"APPROVE", "COMMENT", "REQUEST_CHANGES"} {
		t.Run(verdict, func(t *testing.T) {
			gh := newFakeGH(t, reviewResponses("mesbrj"))
			r := runPostReview(t, gh, patchedScript(t, "post_review.py"), findings(t, verdict), "JUDGE_BOT_LOGIN=review-bot[bot]")
			require.Equal(t, 0, r.code, r.output())

			body, _ := submittedReview(t, gh.calls())["body"].(string)
			require.Contains(t, body, "## TL;DR")
			if verdict == "COMMENT" {
				assert.NotContains(t, body, "Intended verdict")
				return
			}
			assert.True(t, strings.HasSuffix(body, "Intended verdict: **"+verdict+"**"), "body ends with %q", body[max(0, len(body)-80):])
		})
	}
}

// normalizedCalls makes two runs comparable: the temp file passed with --input
// differs per run, its content does not.
func normalizedCalls(calls []ghCall) []ghCall {
	out := make([]ghCall, len(calls))
	for i, c := range calls {
		args := append([]string{}, c.Args...)
		for j := 0; j < len(args)-1; j++ {
			if args[j] == "--input" {
				args[j+1] = "<input>"
			}
		}
		out[i] = ghCall{Args: args, Key: c.Key, Input: c.Input}
	}
	return out
}

// C50 (AC 41): over each of the 4 inputs.
func TestPostReview_WithoutBotLoginMatchesUpstream(t *testing.T) {
	upstream := filepath.Join(upstreamDir(t), "post_review.py")
	cases := []struct{ name, verdict, author string }{
		{"APPROVE on the caller's own pull request", "APPROVE", "mesbrj"},
		{"APPROVE on another author's pull request", "APPROVE", "someone"},
		{"REQUEST_CHANGES on another author's pull request", "REQUEST_CHANGES", "someone"},
		{"COMMENT on another author's pull request", "COMMENT", "someone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := findings(t, tc.verdict)

			gh := newFakeGH(t, reviewResponses(tc.author))
			want := runPostReview(t, gh, upstream, in)
			wantCalls := normalizedCalls(gh.calls())
			require.Equal(t, 0, want.code, want.output())

			gh.respond(reviewResponses(tc.author))
			got := runPostReview(t, gh, patchedScript(t, "post_review.py"), in)
			require.Equal(t, 0, got.code, got.output())

			require.NotEmpty(t, wantCalls)
			assert.Equal(t, wantCalls, normalizedCalls(gh.calls()))
			assert.Equal(t, want.stdout, got.stdout)
		})
	}
}

// C51 (AC 42)
func TestPostReview_CarriesModificationNotice(t *testing.T) {
	assertModificationNotice(t, patchedScript(t, "post_review.py"), "JUDGE_BOT_LOGIN")
}

// --- scan_bypasses.py -----------------------------------------------------

// addedLineDiff is a unified diff that adds line as line 11 of path.
func addedLineDiff(path, line string) string {
	return "diff --git a/" + path + " b/" + path + "\n" +
		"--- a/" + path + "\n+++ b/" + path + "\n" +
		"@@ -10,2 +10,3 @@\n context before\n+" + line + "\n context after\n"
}

func scan(t *testing.T, script, diff string) result {
	t.Helper()
	cmd := exec.Command("python3", script) // #nosec G204 -- a vendored script named by the test
	cmd.Stdin = strings.NewReader(diff)
	cmd.Env = cleanEnv()
	return run(t, cmd)
}

// C52 (AC 43)
func TestScanBypasses_ReportsGoTimeSleep(t *testing.T) {
	diff := addedLineDiff("internal/x/x.go", "\ttime.Sleep(100 * time.Millisecond)")

	r := scan(t, patchedScript(t, "scan_bypasses.py"), diff)
	require.Equal(t, 0, r.code, r.output())
	lines := nonEmptyLines(r.stdout)
	require.Len(t, lines, 1, r.stdout)
	fields := strings.Split(lines[0], "\t")
	require.Len(t, fields, 3, lines[0])
	assert.Equal(t, "internal/x/x.go:11", fields[0])
	assert.Equal(t, "sync-hack", fields[1])
	assert.Equal(t, "time.Sleep(100 * time.Millisecond)", fields[2])

	// Upstream misses it: the patch is what reports it.
	up := scan(t, filepath.Join(upstreamDir(t), "scan_bypasses.py"), diff)
	require.Equal(t, 0, up.code, up.output())
	assert.Empty(t, nonEmptyLines(up.stdout))
}

// C53 (AC 44): one added line per upstream v1.4.0 marker, in MARKERS order.
func TestScanBypasses_ReportsEveryUpstreamMarker(t *testing.T) {
	markers := []struct{ category, line string }{
		{"suppression", "// eslint-disable-next-line no-console"},
		{"suppression", "// @ts-ignore"},
		{"suppression", "import os  # noqa: F401"},
		{"suppression", "x = y  # type: ignore"},
		{"suppression", "# pylint: disable=broad-except"},
		{"suppression", "# rubocop:disable Metrics/AbcSize"},
		{"suppression", `@SuppressWarnings("unchecked")`},
		{"suppression", "v := f() //nolint:errcheck"},
		{"suppression", "// biome-ignore lint/style: legacy"},
		{"suppression", "#pragma warning disable 4996"},
		{"test-dodge", `it.only("runs", () => {})`},
		{"test-dodge", `xit("pending", () => {})`},
		{"test-dodge", "@pytest.mark.skip"},
		{"test-dodge", `t.Skip("needs root")`},
		{"hook-bypass", "git commit --no-verify -m wip"},
		{"tls-bypass", "InsecureSkipVerify: true,"},
		{"type-bypass", "const v = y as any;"},
		{"error-swallow", "except: pass"},
		{"unsafe-html", "<div dangerouslySetInnerHTML={{ __html: html }} />"},
		{"sync-hack", "time.sleep(1)"},
	}

	upstreamSrc, err := os.ReadFile(filepath.Join(upstreamDir(t), "scan_bypasses.py"))
	require.NoError(t, err)
	require.Len(t, markers, len(regexp.MustCompile(`(?m)^\s*\("[a-z-]+", re\.compile\(`).FindAll(upstreamSrc, -1)),
		"one case per upstream marker")

	upstream := filepath.Join(upstreamDir(t), "scan_bypasses.py")
	for i, m := range markers {
		t.Run(fmt.Sprintf("%02d %s", i+1, m.category), func(t *testing.T) {
			diff := addedLineDiff("src/file.txt", m.line)
			want := scan(t, upstream, diff)
			got := scan(t, patchedScript(t, "scan_bypasses.py"), diff)
			require.Equal(t, 0, want.code, want.output())
			require.Equal(t, 0, got.code, got.output())

			lines := nonEmptyLines(want.stdout)
			require.Len(t, lines, 1, "upstream must report the sample: %q", want.stdout)
			assert.Equal(t, "src/file.txt:11\t"+m.category, strings.Join(strings.Split(lines[0], "\t")[:2], "\t"))
			assert.Equal(t, want.stdout, got.stdout)
		})
	}
}

// C54 (AC 45)
func TestScanBypasses_CarriesModificationNotice(t *testing.T) {
	assertModificationNotice(t, patchedScript(t, "scan_bypasses.py"), "time.Sleep")
}
