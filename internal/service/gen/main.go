// Command gen parses internal/service/auditlog.go and internal/connect/
// metrics.go and emits a stable, sorted JSON description of the audit-event
// vocabulary (AdminAction + TupleOpKind constants) and the Prometheus metric
// names, to docs-site/src/data/generated/audit-events.json. The observability
// docs render from this file so it can never drift from the code.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// auditEvent is one audit event-type string constant with its doc comment.
type auditEvent struct {
	Name        string `json:"name"`        // the string value, e.g. "create_project"
	Kind        string `json:"kind"`        // AdminAction | TupleOpKind
	Const       string `json:"const"`       // the Go const identifier
	Description string `json:"description"` // doc comment
}

// metric is one Prometheus metric name + help text.
type metric struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type payload struct {
	Events  []auditEvent `json:"events"`
	Metrics []metric     `json:"metrics"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "audit gen:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	events, err := parseEvents(filepath.Join(root, "internal", "service", "auditlog.go"))
	if err != nil {
		return err
	}
	metrics, err := parseMetrics(filepath.Join(root, "internal", "connect", "metrics.go"))
	if err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Name < events[j].Name })
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].Name < metrics[j].Name })

	out := filepath.Join(root, "docs-site", "src", "data", "generated", "audit-events.json")
	if dir := os.Getenv("DOCS_GEN_OUT"); dir != "" {
		out = filepath.Join(dir, "audit-events.json")
	}
	return writeJSON(out, payload{Events: events, Metrics: metrics})
}

// parseEvents extracts string constants of the named audit types with their
// doc comments.
func parseEvents(src string) ([]auditEvent, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", src, err)
	}
	wanted := map[string]bool{"AdminAction": true, "TupleOpKind": true}
	var events []auditEvent
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			kind := typeName(vs.Type)
			if !wanted[kind] || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			val, ok := stringLit(vs.Values[0])
			if !ok {
				continue
			}
			doc := ""
			if vs.Doc != nil {
				doc = oneLine(vs.Doc.Text())
			}
			events = append(events, auditEvent{
				Name: val, Kind: kind, Const: vs.Names[0].Name, Description: doc,
			})
		}
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("no audit-event constants parsed from %s", src)
	}
	return events, nil
}

// parseMetrics extracts metric names from prometheus.*Opts{Name: "...", Help:
// "..."} composite literals.
func parseMetrics(src string) ([]metric, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", src, err)
	}
	var metrics []metric
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || !strings.HasSuffix(sel.Sel.Name, "Opts") {
			return true
		}
		var name, help string
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Name":
				name, _ = stringLit(kv.Value)
			case "Help":
				help, _ = stringLit(kv.Value)
			}
		}
		if strings.HasPrefix(name, "authz_") {
			metrics = append(metrics, metric{Name: name, Description: help})
		}
		return true
	})
	if len(metrics) == 0 {
		return nil, fmt.Errorf("no authz_ metrics parsed from %s", src)
	}
	return metrics, nil
}

func typeName(expr ast.Expr) string {
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func stringLit(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}
