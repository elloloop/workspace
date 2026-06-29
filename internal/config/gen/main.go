// Command gen parses internal/config/config.go and emits a stable, sorted
// JSON description of every GATEWAY_ environment knob the service reads, to
// docs-site/src/data/generated/config.json. It is the single source the docs
// configuration table renders from, so the page can never drift from the code.
//
// It resolves the four env helpers (envInt/envBool/envStr/envCSV), follows
// named-constant defaults (e.g. DefaultMaxListObjects) to their literal value,
// maps each Config struct field to its env var via the Load() assignment to
// pull the human description from the field's doc comment, and flags a knob as
// constrained when its env name appears in Validate().
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

// knob is one documented configuration variable. The JSON shape the docs site
// imports: {name, type, default, required, description, constraint?}.
type knob struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // int | bool | string | csv
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Constraint  string `json:"constraint,omitempty"`
}

// envHelpers maps the helper name to the logical type it yields.
var envHelpers = map[string]string{
	"envInt":  "int",
	"envBool": "bool",
	"envStr":  "string",
	"envCSV":  "csv",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "config gen:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	src := filepath.Join(root, "internal", "config", "config.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parse %s: %w", src, err)
	}

	consts := collectConsts(file)
	fieldDocs := collectFieldDocs(file)
	loadAssign := collectLoadAssignments(file) // field name -> env call expr
	validateNames := collectValidateEnvNames(file)
	validateMsgs := collectValidateConstraints(file, consts)

	var knobs []knob
	for field, call := range loadAssign {
		k, ok := knobFromCall(call, consts)
		if !ok {
			continue
		}
		k.Description = oneLine(fieldDocs[field])
		k.Required = false // every knob has a default; none are strictly required
		if validateNames[k.Name] {
			k.Constraint = validateMsgs[k.Name]
		}
		knobs = append(knobs, k)
	}
	if len(knobs) == 0 {
		return fmt.Errorf("no GATEWAY_ knobs parsed from %s", src)
	}
	sort.Slice(knobs, func(i, j int) bool { return knobs[i].Name < knobs[j].Name })

	return writeJSON(outPath(root, "config.json"), knobs)
}

// knobFromCall extracts a knob from an env{Int,Bool,Str,CSV}(...) call, or
// reports ok=false when the expression is not one of those helpers.
func knobFromCall(call *ast.CallExpr, consts map[string]string) (knob, bool) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return knob{}, false
	}
	typ, ok := envHelpers[ident.Name]
	if !ok {
		return knob{}, false
	}
	if len(call.Args) == 0 {
		return knob{}, false
	}
	name, ok := stringLit(call.Args[0])
	if !ok || !strings.HasPrefix(name, "GATEWAY_") {
		return knob{}, false
	}
	k := knob{Name: name, Type: typ}
	switch typ {
	case "csv":
		k.Default = "" // CSV helpers take no default; empty/unset yields none
	default:
		if len(call.Args) >= 2 {
			k.Default = literalValue(call.Args[1], consts)
		}
	}
	return k, true
}

// collectConsts records every top-level string/int/bool const so named
// defaults (DefaultMaxListObjects, etc.) resolve to their literal value.
func collectConsts(file *ast.File) map[string]string {
	consts := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			consts[vs.Names[0].Name] = literalValue(vs.Values[0], consts)
		}
	}
	return consts
}

// collectFieldDocs maps each Config struct field name to its doc comment.
func collectFieldDocs(file *ast.File) map[string]string {
	docs := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != "Config" {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 || f.Doc == nil {
					continue
				}
				docs[f.Names[0].Name] = f.Doc.Text()
			}
		}
	}
	return docs
}

// collectLoadAssignments returns, for the composite literal built in Load(),
// each Config field name mapped to the env call expression assigned to it.
func collectLoadAssignments(file *ast.File) map[string]*ast.CallExpr {
	out := map[string]*ast.CallExpr{}
	fn := findFunc(file, "Load")
	if fn == nil {
		return out
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "Config" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			// The value is either the env call directly or wrapped (e.g.
			// int64(envInt(...))). Find the first env-helper call inside it.
			if call := findEnvCall(kv.Value); call != nil {
				out[key.Name] = call
			}
		}
		return true
	})
	return out
}

// findEnvCall returns the first env{Int,Bool,Str,CSV} call within expr,
// unwrapping conversions like int64(envInt(...)).
func findEnvCall(expr ast.Expr) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			if _, isHelper := envHelpers[id.Name]; isHelper {
				found = call
				return false
			}
		}
		return true
	})
	return found
}

// collectValidateEnvNames returns the set of GATEWAY_ names referenced in any
// string literal inside Validate() — i.e. knobs with a floor/constraint.
func collectValidateEnvNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	fn := findFunc(file, "Validate")
	if fn == nil {
		return names
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		for _, tok := range strings.Fields(v) {
			tok = strings.Trim(tok, ",.:%\"'()")
			if strings.HasPrefix(tok, "GATEWAY_") {
				names[tok] = true
			}
		}
		return true
	})
	return names
}

// collectValidateConstraints maps each GATEWAY_ name to a short human
// constraint string built from the validation message it appears in, with
// named-constant floors resolved to their value.
func collectValidateConstraints(file *ast.File, consts map[string]string) map[string]string {
	out := map[string]string{}
	fn := findFunc(file, "Validate")
	if fn == nil {
		return out
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// fmt.Errorf / errors.New: arg 0 is the format/message string.
		if len(call.Args) == 0 {
			return true
		}
		msg, ok := stringLit(call.Args[0])
		if !ok {
			return true
		}
		name := ""
		for _, tok := range strings.Fields(msg) {
			t := strings.Trim(tok, ",.:%\"'()")
			if strings.HasPrefix(t, "GATEWAY_") {
				name = t
				break
			}
		}
		if name == "" {
			return true
		}
		c := humanizeConstraint(msg, call.Args[1:], consts)
		// Skip messages that only echo a runtime field value (e.g. "out of
		// range: <port>") — the constraint phrase carries no static floor and
		// reads as noise. Keep only constraints that resolved a real bound.
		if c == "" || strings.Contains(c, "…") {
			return true
		}
		out[name] = c
		return true
	})
	return out
}

// humanizeConstraint turns an Errorf message + args into a compact constraint
// phrase, substituting %d/%q verbs with the resolved literal of each arg.
func humanizeConstraint(msg string, args []ast.Expr, consts map[string]string) string {
	for _, a := range args {
		val := literalValue(a, consts)
		if val == "" {
			val = "…"
		}
		for _, verb := range []string{"%d", "%q", "%s", "%v"} {
			if strings.Contains(msg, verb) {
				msg = strings.Replace(msg, verb, val, 1)
				break
			}
		}
	}
	// Drop the leading "GATEWAY_NAME " so the phrase reads as a constraint.
	fields := strings.Fields(msg)
	if len(fields) > 1 && strings.HasPrefix(fields[0], "GATEWAY_") {
		msg = strings.TrimSpace(strings.TrimPrefix(msg, fields[0]))
	}
	return oneLine(msg)
}

// literalValue resolves an expression to its literal string form: basic
// literals, named constants, and simple binary shifts (1<<20).
func literalValue(expr ast.Expr, consts map[string]string) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if v, err := strconv.Unquote(e.Value); err == nil {
				return v
			}
		}
		return e.Value
	case *ast.Ident:
		switch e.Name {
		case "true", "false":
			return e.Name
		}
		if v, ok := consts[e.Name]; ok {
			return v
		}
		return ""
	case *ast.BinaryExpr:
		if e.Op == token.SHL {
			l := literalValue(e.X, consts)
			r := literalValue(e.Y, consts)
			if li, err1 := strconv.Atoi(l); err1 == nil {
				if ri, err2 := strconv.Atoi(r); err2 == nil {
					return strconv.Itoa(li << ri)
				}
			}
		}
	case *ast.CallExpr:
		// Unwrap conversions like int64(<lit>).
		if len(e.Args) == 1 {
			return literalValue(e.Args[0], consts)
		}
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

func findFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// oneLine collapses a doc comment into a single trimmed sentence-ish line.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// outPath resolves the destination for a generated JSON file. DOCS_GEN_OUT
// overrides the directory (used by the freshness test to generate into a temp
// dir); otherwise it lands under the committed docs-site data tree.
func outPath(root, name string) string {
	if dir := os.Getenv("DOCS_GEN_OUT"); dir != "" {
		return filepath.Join(dir, name)
	}
	return filepath.Join(root, "docs-site", "src", "data", "generated", name)
}

func repoRoot() (string, error) {
	// Resolve relative to this source file's package so `go generate` from any
	// cwd writes to the right place: gen/ -> config/ -> internal/ -> root.
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Walk up until we find go.mod.
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
