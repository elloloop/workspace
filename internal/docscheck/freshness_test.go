package docscheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// generatedFiles are the codegen outputs that must match a fresh generation.
var generatedFiles = []string{"config.json", "audit-events.json"}

// generators maps each Go generator package (relative to the module root) to
// the file it produces, so a single run regenerates everything into a temp dir.
var generators = []string{
	"./internal/config/gen",
	"./internal/service/gen",
}

// TestGeneratedDocsAreFresh regenerates the reference JSON into a temp dir and
// fails if the committed files differ — so a code change that should have been
// followed by `make docs-gen` cannot land stale docs data.
func TestGeneratedDocsAreFresh(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()

	for _, pkg := range generators {
		cmd := exec.Command("go", "run", pkg) //nolint:gosec // pkg is a fixed in-repo generator path
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "DOCS_GEN_OUT="+tmp)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("regenerate %s: %v\n%s", pkg, err, out)
		}
	}

	committedDir := filepath.Join(root, "docs-site", "src", "data", "generated")
	for _, name := range generatedFiles {
		fresh := readFile(t, filepath.Join(tmp, name))
		committed := readFile(t, filepath.Join(committedDir, name))
		if fresh != committed {
			t.Errorf("%s is stale — run `make docs-gen` and commit the result", name)
		}
	}
}
