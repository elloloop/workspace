package authz

import (
	"context"
	"fmt"
	"testing"
)

// TestNestedResourceInheritance: a resource whose parent is ANOTHER resource
// inherits editor/viewer transitively up the folder chain.
//
//	folderA ⊃ folderB ⊃ doc   (parent pointers)
func TestNestedResourceInheritance(t *testing.T) {
	r := &fakeReader{}
	r.add("resource", "doc", "parent", set("resource", "folderB", "viewer"))
	r.add("resource", "folderB", "parent", set("resource", "folderA", "viewer"))
	r.add("resource", "folderA", "editor", user("alice")) // editor two levels up
	r.add("resource", "folderB", "viewer", user("bob"))   // viewer one level up
	e := NewEngine(nil, r)
	ctx := context.Background()

	chk := func(obj, rel, who string) bool {
		ok, err := e.Check(ctx, "p", "", "resource", obj, rel, who, nil)
		if err != nil {
			t.Fatalf("Check %s#%s@%s: %v", obj, rel, who, err)
		}
		return ok
	}

	// alice has editor on folderA → editor (and thus viewer) flows to doc.
	if !chk("doc", "editor", "alice") {
		t.Fatal("alice should inherit editor on doc from folderA")
	}
	if !chk("doc", "viewer", "alice") {
		t.Fatal("editor implies viewer on doc for alice")
	}
	// bob has viewer on folderB → viewer flows down to doc, but NOT up to folderA.
	if !chk("doc", "viewer", "bob") {
		t.Fatal("bob should inherit viewer on doc from folderB")
	}
	if chk("folderA", "viewer", "bob") {
		t.Fatal("inheritance flows down, not up: bob must NOT have viewer on folderA")
	}
	if chk("doc", "editor", "bob") {
		t.Fatal("bob only has viewer, not editor, on doc")
	}
	// A user with nothing is denied.
	if chk("doc", "viewer", "carol") {
		t.Fatal("carol has no grant anywhere; doc viewer must be denied")
	}
}

// TestWorkspaceRootedResourceUnchanged: a resource whose parent is a WORKSPACE
// still inherits admin→editor / member→viewer exactly as before (no regression
// from adding the resource-parent legs).
func TestWorkspaceRootedResourceUnchanged(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "admin", user("alice"))
	r.add("workspace", "w1", "member", user("bob"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	e := NewEngine(nil, r)
	ctx := context.Background()

	chk := func(rel, who string) bool {
		ok, err := e.Check(ctx, "p", "", "resource", "doc1", rel, who, nil)
		if err != nil {
			t.Fatalf("Check doc1#%s@%s: %v", rel, who, err)
		}
		return ok
	}
	if !chk("editor", "alice") {
		t.Fatal("workspace admin should still inherit editor on the resource")
	}
	if !chk("viewer", "bob") {
		t.Fatal("workspace member should still inherit viewer on the resource")
	}
	if chk("editor", "bob") {
		t.Fatal("a plain member must NOT inherit editor")
	}
}

// TestDeepResourceChainNoSpuriousError: a long resource→resource chain (well
// under the engine's maxDepth) resolves correctly without erroring.
func TestDeepResourceChainNoSpuriousError(t *testing.T) {
	const depth = 10
	r := &fakeReader{}
	for i := 0; i < depth-1; i++ {
		child := fmt.Sprintf("f%d", i)
		parent := fmt.Sprintf("f%d", i+1)
		r.add("resource", child, "parent", set("resource", parent, "viewer"))
	}
	top := fmt.Sprintf("f%d", depth-1)
	r.add("resource", top, "editor", user("alice"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "", "resource", "f0", "viewer", "alice", nil)
	if err != nil {
		t.Fatalf("deep chain should not error: %v", err)
	}
	if !ok {
		t.Fatalf("alice's editor at the top of a %d-level chain should grant viewer at the bottom", depth)
	}
}
