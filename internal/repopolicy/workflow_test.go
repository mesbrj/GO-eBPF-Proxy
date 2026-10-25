package repopolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// workflow is the subset of a GitHub Actions workflow the checks read.
type workflow struct {
	On          any            `yaml:"on"`
	Permissions any            `yaml:"permissions"`
	Jobs        map[string]job `yaml:"jobs"`
}

type job struct {
	If          string     `yaml:"if"`
	Needs       stringList `yaml:"needs"`
	RunsOn      any        `yaml:"runs-on"`
	Environment any        `yaml:"environment"`
	Permissions any        `yaml:"permissions"`
	Strategy    struct {
		Matrix map[string]any `yaml:"matrix"`
	} `yaml:"strategy"`
	Outputs map[string]string `yaml:"outputs"`
	Steps   []step            `yaml:"steps"`
}

type step struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

// stringList decodes a YAML scalar or sequence of strings.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = []string{n.Value}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*s = l
	return nil
}

// workflowFile is one parsed file under .github/workflows.
type workflowFile struct {
	name string // base name, e.g. ci.yml
	raw  []byte
	root *yaml.Node // the document's top-level mapping
	wf   workflow
}

func parseWorkflow(name string, raw []byte) (workflowFile, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return workflowFile{}, fmt.Errorf("%s: %w", name, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return workflowFile{}, fmt.Errorf("%s: not a YAML mapping", name)
	}
	f := workflowFile{name: name, raw: raw, root: doc.Content[0]}
	if err := f.root.Decode(&f.wf); err != nil {
		return workflowFile{}, fmt.Errorf("%s: %w", name, err)
	}
	return f, nil
}

func loadWorkflowDir(t *testing.T, dir string) []workflowFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var files []workflowFile
	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a workflow file under the directory the test named
		require.NoError(t, err)
		f, err := parseWorkflow(e.Name(), raw)
		require.NoError(t, err)
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return files
}

func repoWorkflows(t *testing.T) []workflowFile {
	t.Helper()
	files := loadWorkflowDir(t, repoPath(t, ".github/workflows"))
	require.NotEmpty(t, files)
	return files
}

func repoWorkflow(t *testing.T, name string) workflowFile {
	t.Helper()
	f, ok := findWorkflow(repoWorkflows(t), name)
	require.True(t, ok, "workflow %s not found", name)
	return f
}

func findWorkflow(files []workflowFile, name string) (workflowFile, bool) {
	for _, f := range files {
		if f.name == name {
			return f, true
		}
	}
	return workflowFile{}, false
}

func (f workflowFile) job(t *testing.T, name string) job {
	t.Helper()
	j, ok := f.wf.Jobs[name]
	require.True(t, ok, "%s has no job %s", f.name, name)
	return j
}

func (f workflowFile) jobNames() []string {
	names := make([]string, 0, len(f.wf.Jobs))
	for n := range f.wf.Jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// jobNode returns the YAML node of the named job, for checks over its text.
func (f workflowFile) jobNode(t *testing.T, name string) *yaml.Node {
	t.Helper()
	jobs := mappingValue(f.root, "jobs")
	require.NotNil(t, jobs, "%s has no jobs", f.name)
	n := mappingValue(jobs, name)
	require.NotNil(t, n, "%s has no job %s", f.name, name)
	return n
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func nodeText(t *testing.T, n *yaml.Node) string {
	t.Helper()
	b, err := yaml.Marshal(n)
	require.NoError(t, err)
	return string(b)
}

// triggers returns the workflow's events, whichever of the three forms on: takes.
func triggers(wf workflow) map[string]any {
	out := map[string]any{}
	switch on := wf.On.(type) {
	case string:
		out[on] = nil
	case []any:
		for _, e := range on {
			out[fmt.Sprint(e)] = nil
		}
	case map[string]any:
		for k, v := range on {
			out[k] = v
		}
	}
	return out
}

// usesNode is one uses: value with the comment on its line.
type usesNode struct {
	value, comment string
}

// allUses walks the whole file, so a uses: anywhere (step or reusable job) counts.
func allUses(n *yaml.Node) []usesNode {
	var out []usesNode
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k, v := n.Content[i], n.Content[i+1]; k.Value == "uses" && v.Kind == yaml.ScalarNode {
					out = append(out, usesNode{value: v.Value, comment: v.LineComment})
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return out
}

// usesRepo splits owner/repo[/path]@ref into owner and repo.
func usesRepo(uses string) (owner, repo string) {
	ref, _, _ := strings.Cut(uses, "@")
	parts := strings.Split(ref, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func stepUsing(j job, actionPrefix string) (step, bool) {
	for _, s := range j.Steps {
		if strings.HasPrefix(s.Uses, actionPrefix) {
			return s, true
		}
	}
	return step{}, false
}

// stepIndex returns the index of the first step whose run: script matches re, or -1.
func stepIndex(j job, re *regexp.Regexp) int {
	for i, s := range j.Steps {
		if re.MatchString(s.Run) {
			return i
		}
	}
	return -1
}

func environmentName(env any) string {
	switch e := env.(type) {
	case string:
		return e
	case map[string]any:
		return fmt.Sprint(e["name"])
	}
	return ""
}

// copyWorkflows copies the committed workflows into dir/.github/workflows and
// returns that directory.
func copyWorkflows(t *testing.T, dir string) string {
	t.Helper()
	dst := filepath.Join(dir, ".github", "workflows")
	require.NoError(t, os.MkdirAll(dst, 0o700))
	src := repoPath(t, ".github/workflows")
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name())) // #nosec G304 -- a committed workflow file
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600)) // #nosec G703 -- a temp copy under t.TempDir
	}
	return dst
}

// mutateFile replaces the first match of old (a literal) in dir/name with repl,
// failing when old is absent so a stale anchor cannot pass silently.
func mutateFile(t *testing.T, dir, name, old, repl string) {
	t.Helper()
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path) // #nosec G304 -- a temp copy written by the test
	require.NoError(t, err)
	require.Contains(t, string(b), old, "mutation anchor missing in %s", name)
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(b), old, repl, 1)), 0o600)) // #nosec G703 -- a temp copy under t.TempDir
}

// mutateFileRegexp is mutateFile with a regular expression.
func mutateFileRegexp(t *testing.T, dir, name, pattern, repl string) {
	t.Helper()
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path) // #nosec G304 -- a temp copy written by the test
	require.NoError(t, err)
	re := regexp.MustCompile(pattern)
	loc := re.FindIndex(b)
	require.NotNil(t, loc, "mutation pattern %q missing in %s", pattern, name)
	out := append(append(append([]byte{}, b[:loc[0]]...), repl...), b[loc[1]:]...)
	require.NoError(t, os.WriteFile(path, out, 0o600)) // #nosec G703 -- a temp copy under t.TempDir
}
