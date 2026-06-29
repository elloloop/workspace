// Package docscheck holds CI guards that keep the documentation honest about
// the code it describes. The drift test scans every prose file under docs-site/
// and docs/ and fails if it NAMES a code identifier — an env var, an RPC, a
// metric, an audit event, or a repo file path — that does not exist in source.
// It does not verify that the prose is correct, only that every identifier it
// references is real, so a renamed knob or RPC can never leave a dangling
// reference in the docs.
package docscheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from this test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// docDirs are the prose trees scanned for code references.
var docDirs = []string{
	filepath.Join("docs-site", "src"),
	"docs",
}

// skipDirs are subtrees that hold generated/build output or vendored assets,
// never hand-written prose.
var skipDirs = map[string]bool{
	"node_modules": true,
	"dist":         true,
	".astro":       true,
	"generated":    true, // codegen output is validated by the freshness test
	"public":       true, // mirrors of proto/openapi, validated upstream
}

func collectDocFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, d := range docDirs {
		base := filepath.Join(root, d)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".astro", ".md", ".mdx", ".html":
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("no documentation files found to scan")
	}
	return files
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test reads repo files under a fixed root
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- valid-identifier sources (ground truth from code) ----

// validEnvNames returns the GATEWAY_ knobs the config generator emits, plus any
// referenced directly in config.go (a superset is fine — we only flag tokens
// that match NONE of these).
func validEnvNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	// From the generated config.json.
	var knobs []struct {
		Name string `json:"name"`
	}
	data := readFile(t, filepath.Join(root, "docs-site", "src", "data", "generated", "config.json"))
	if err := json.Unmarshal([]byte(data), &knobs); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	for _, k := range knobs {
		names[k.Name] = true
	}
	// Also anything literally named in config.go (e.g. GATEWAY_SERVICE_CREDENTIALS,
	// GATEWAY_TEST_POSTGRES_DSN) that the generator does not surface.
	cfg := readFile(t, filepath.Join(root, "internal", "config", "config.go"))
	for _, m := range envTokenRE.FindAllString(cfg, -1) {
		names[m] = true
	}
	return names
}

func validRPCs(t *testing.T, root string) map[string]bool {
	t.Helper()
	proto := readFile(t, filepath.Join(root, "proto", "workspace", "v1", "workspace.proto"))
	out := map[string]bool{}
	for _, m := range rpcDeclRE.FindAllStringSubmatch(proto, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("no rpc declarations found in workspace.proto")
	}
	return out
}

// validGoFuncs collects exported Go function/method names declared in pkg/ and
// internal/. A CamelCase code token that resolves to one of these is a real
// engine primitive (e.g. CheckSet) referenced as a concept, not a dangling RPC
// reference, so it must not be flagged.
func validGoFuncs(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, dir := range []string{"pkg", "internal", "workspaceserver"} {
		base := filepath.Join(root, dir)
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			for _, m := range goFuncRE.FindAllStringSubmatch(readFile(t, path), -1) {
				out[m[1]] = true
			}
			return nil
		})
	}
	return out
}

func validMetricsAndEvents(t *testing.T, root string) (metrics, events map[string]bool) {
	t.Helper()
	metrics, events = map[string]bool{}, map[string]bool{}
	var payload struct {
		Events  []struct{ Name string } `json:"events"`
		Metrics []struct{ Name string } `json:"metrics"`
	}
	data := readFile(t, filepath.Join(root, "docs-site", "src", "data", "generated", "audit-events.json"))
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatalf("parse audit-events.json: %v", err)
	}
	for _, e := range payload.Events {
		events[e.Name] = true
	}
	for _, m := range payload.Metrics {
		metrics[m.Name] = true
	}
	return metrics, events
}

// ---- extraction patterns ----

var (
	// GATEWAY_ env tokens anywhere in prose.
	envTokenRE = regexp.MustCompile(`GATEWAY_[A-Z0-9_]+`)
	// rpc <Name>( in the proto.
	rpcDeclRE = regexp.MustCompile(`rpc\s+([A-Za-z][A-Za-z0-9]*)\s*\(`)
	// authz_*_total / authz_*_seconds / authz_*_items metric tokens.
	metricTokenRE = regexp.MustCompile(`authz_[a-z0-9_]+`)
	// CamelCase tokens wrapped in <code>…</code> or backticks — RPC candidates.
	codeTokenRE = regexp.MustCompile("(?:<code>([A-Z][A-Za-z0-9]*)</code>|`([A-Z][A-Za-z0-9]*)`)")
	// Repo-relative .go paths (internal/..., pkg/..., cmd/..., workspaceserver/...).
	goPathRE = regexp.MustCompile(`\b((?:internal|pkg|cmd|workspaceserver|tests|gen)/[A-Za-z0-9_./-]+\.go)\b`)
	// Exported Go func/method declarations: `func Name(` or `func (r T) Name(`.
	goFuncRE = regexp.MustCompile(`func\s+(?:\([^)]*\)\s*)?([A-Z][A-Za-z0-9]*)\s*(?:\[[^\]]*\]\s*)?\(`)
)

// rpcVerbPrefixes are the verbs the service's RPC names start with. A code
// token is only treated as an RPC reference (and thus required to exist) when
// it begins with one of these — this keeps non-RPC CamelCase tokens like
// AuthzService, Namespace, or SubjectSet from being flagged.
var rpcVerbPrefixes = []string{
	"Accept", "Add", "Assign", "BatchCheck", "Check", "Create", "Deprovision",
	"Delete", "Expand", "Export", "Get", "List", "ListObjects", "Reinstate",
	"Remove", "Revoke", "Set", "Suspend", "Transfer", "Update", "Write", "Read",
}

func looksLikeRPC(tok string) bool {
	for _, p := range rpcVerbPrefixes {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	return false
}

// TestDocsReferencesExist fails listing every identifier referenced in prose
// that does not exist in source.
func TestDocsReferencesExist(t *testing.T) {
	root := repoRoot(t)
	envNames := validEnvNames(t, root)
	rpcs := validRPCs(t, root)
	goFuncs := validGoFuncs(t, root)
	metrics, events := validMetricsAndEvents(t, root)
	files := collectDocFiles(t, root)

	type miss struct {
		file, kind, token string
	}
	var misses []miss
	seen := map[string]bool{}
	add := func(file, kind, token string) {
		key := kind + "|" + token + "|" + file
		if seen[key] {
			return
		}
		seen[key] = true
		misses = append(misses, miss{file, kind, token})
	}

	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		content := readFile(t, f)

		for _, tok := range envTokenRE.FindAllString(content, -1) {
			if !envNames[tok] {
				add(rel, "env", tok)
			}
		}
		for _, tok := range metricTokenRE.FindAllString(content, -1) {
			if !metrics[tok] {
				add(rel, "metric", tok)
			}
		}
		for _, m := range codeTokenRE.FindAllStringSubmatch(content, -1) {
			tok := m[1]
			if tok == "" {
				tok = m[2]
			}
			if looksLikeRPC(tok) && !rpcs[tok] && !goFuncs[tok] {
				add(rel, "rpc", tok)
			}
		}
		for _, m := range goPathRE.FindAllStringSubmatch(content, -1) {
			p := m[1]
			if _, err := os.Stat(filepath.Join(root, p)); err != nil {
				add(rel, "path", p)
			}
		}
		// Audit-event strings referenced in prose, e.g. "create_project".
		for _, name := range []string{"create_project", "update_project"} {
			if strings.Contains(content, `"`+name+`"`) && !events[name] {
				add(rel, "audit-event", name)
			}
		}
	}

	if len(misses) == 0 {
		return
	}
	sort.Slice(misses, func(i, j int) bool {
		if misses[i].kind != misses[j].kind {
			return misses[i].kind < misses[j].kind
		}
		if misses[i].token != misses[j].token {
			return misses[i].token < misses[j].token
		}
		return misses[i].file < misses[j].file
	})
	var b strings.Builder
	b.WriteString("documentation references identifiers that do not exist in source:\n")
	for _, m := range misses {
		b.WriteString("  [" + m.kind + "] " + m.token + "  (" + m.file + ")\n")
	}
	t.Fatal(b.String())
}
