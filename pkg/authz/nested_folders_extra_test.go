package authz

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// countingReader wraps fakeReader and counts ListSubjects calls, to prove
// request-scoped memoization collapses the folder-DAG fan-out.
type countingReader struct {
	*fakeReader
	mu sync.Mutex
	n  int
}

func (c *countingReader) ListSubjects(ctx context.Context, p, t, ns, obj, rel string) ([]Subject, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.fakeReader.ListSubjects(ctx, p, t, ns, obj, rel)
}

// TestWorkspaceEditorTupleDoesNotLeak: editor/viewer on `workspace` are model
// aliases (computed admin/member), so a raw `workspace:w#editor@mallory` tuple is
// inert and cannot leak transitively onto a child resource via the parent leg.
func TestWorkspaceEditorTupleDoesNotLeak(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "editor", user("mallory")) // a raw role-named tuple
	r.add("workspace", "w1", "viewer", user("mallory"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	e := NewEngine(nil, r)
	ctx := context.Background()

	chk := func(ns, obj, rel, who string) bool {
		ok, err := e.Check(ctx, "p", "", ns, obj, rel, who, nil)
		if err != nil {
			t.Fatalf("Check %s:%s#%s@%s: %v", ns, obj, rel, who, err)
		}
		return ok
	}
	// The raw workspace#editor/#viewer tuples are inert (aliases resolve to
	// admin/member, which mallory is not).
	if chk("workspace", "w1", "editor", "mallory") || chk("workspace", "w1", "viewer", "mallory") {
		t.Fatal("raw workspace editor/viewer tuple must be inert (aliases resolve through the model)")
	}
	// ...and therefore cannot leak onto the child resource.
	if chk("resource", "doc1", "editor", "mallory") || chk("resource", "doc1", "viewer", "mallory") {
		t.Fatal("a raw workspace#editor tuple must NOT leak editor/viewer onto a child resource")
	}
}

// TestBranchingResourceDAGMemoized: a linear viewer chain (whose viewer/editor
// legs both recurse into the parent) is evaluated with a LINEAR number of store
// reads thanks to memoization — without it the cost is super-linear.
func TestBranchingResourceDAGMemoized(t *testing.T) {
	const depth = 20
	cr := &countingReader{fakeReader: &fakeReader{}}
	for i := 0; i < depth-1; i++ {
		cr.add("resource", fmt.Sprintf("f%d", i), "parent", set("resource", fmt.Sprintf("f%d", i+1), "viewer"))
	}
	e := NewEngine(nil, cr)

	// Worst case: a DENY walks the whole chain (no early match).
	ok, err := e.Check(context.Background(), "p", "", "resource", "f0", "viewer", "nobody", nil)
	if err != nil || ok {
		t.Fatalf("ungranted deep chain = (%v, %v), want (false, nil)", ok, err)
	}
	// Linear in depth (~a few reads per node). Without memoization the
	// viewer⊃editor double recursion makes this quadratic+ (hundreds).
	if cr.n > 8*depth {
		t.Fatalf("ListSubjects calls = %d for depth %d — memoization not collapsing the fan-out", cr.n, depth)
	}
}

// TestVeryDeepChainFailsClosedGracefully: a chain deeper than maxRecursionDepth
// yields a clean deny (no error → no CodeInternal / DoS), while a within-bound
// deep chain still grants.
func TestVeryDeepChainFailsClosedGracefully(t *testing.T) {
	ctx := context.Background()

	// Past the bound: clean false, no error.
	deep := &fakeReader{}
	for i := 0; i < maxRecursionDepth+50; i++ {
		deep.add("resource", fmt.Sprintf("f%d", i), "parent", set("resource", fmt.Sprintf("f%d", i+1), "viewer"))
	}
	ok, err := NewEngine(nil, deep).Check(ctx, "p", "", "resource", "f0", "viewer", "nobody", nil)
	if err != nil {
		t.Fatalf("over-deep chain must fail closed gracefully, got error: %v", err)
	}
	if ok {
		t.Fatal("over-deep chain for an ungranted user must deny")
	}

	// Within the bound: still grants.
	const ok50 = 50
	within := &fakeReader{}
	for i := 0; i < ok50; i++ {
		within.add("resource", fmt.Sprintf("g%d", i), "parent", set("resource", fmt.Sprintf("g%d", i+1), "viewer"))
	}
	within.add("resource", fmt.Sprintf("g%d", ok50), "editor", user("alice"))
	got, err := NewEngine(nil, within).Check(ctx, "p", "", "resource", "g0", "viewer", "alice", nil)
	if err != nil {
		t.Fatalf("within-bound deep chain errored: %v", err)
	}
	if !got {
		t.Fatalf("alice's editor at level %d should grant viewer at the bottom", ok50)
	}
}

// TestExpandResourceViewer: Expand still resolves resource viewer/editor trees
// (now carrying extra legs) without error, for both a workspace-rooted resource
// and a resource-parent chain.
func TestExpandResourceViewer(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "member", user("bob"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	r.add("resource", "doc2", "parent", set("resource", "doc1", "viewer"))
	e := NewEngine(nil, r)
	ctx := context.Background()

	for _, obj := range []string{"doc1", "doc2"} {
		for _, rel := range []string{"viewer", "editor"} {
			tree, err := e.Expand(ctx, "p", "", "resource", obj, rel, 10000)
			if err != nil {
				t.Fatalf("Expand resource:%s#%s: %v", obj, rel, err)
			}
			if tree.Expanded.Relation != rel || tree.Expanded.ObjectID != obj {
				t.Fatalf("Expand root = %+v, want %s#%s", tree.Expanded, obj, rel)
			}
			if len(tree.Union) == 0 {
				t.Fatalf("Expand resource:%s#%s should be a union of its legs, got %+v", obj, rel, tree)
			}
		}
	}
}
