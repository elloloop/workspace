package authz

import (
	"context"
	"errors"
	"testing"
)

// fakeReader is an in-test TupleReader backed by a flat slice.
type fakeReader struct{ tuples []Tuple }

func (f *fakeReader) add(ns, obj, rel string, s Subject) {
	f.tuples = append(f.tuples, Tuple{Namespace: ns, ObjectID: obj, Relation: rel, Subject: s})
}

func (f *fakeReader) ListSubjects(_ context.Context, _, _, ns, obj, rel string) ([]Subject, error) {
	var out []Subject
	for _, t := range f.tuples {
		if t.Namespace == ns && t.ObjectID == obj && t.Relation == rel {
			out = append(out, t.Subject)
		}
	}
	return out, nil
}

func (f *fakeReader) ListObjectIDs(_ context.Context, _, _, ns string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range f.tuples {
		if t.Namespace == ns && !seen[t.ObjectID] {
			seen[t.ObjectID] = true
			out = append(out, t.ObjectID)
		}
	}
	return out, nil
}

func user(id string) Subject          { return Subject{UserID: id} }
func set(ns, obj, rel string) Subject { return Subject{Set: &SubjectSet{ns, obj, rel}} }

func TestCheckWorkspaceRoleHierarchy(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "owner", user("alice"))
	r.add("workspace", "w1", "member", user("bob"))
	e := NewEngine(StaticResolver(DefaultModel()), r)

	cases := []struct {
		rel, user string
		want      bool
	}{
		{"owner", "alice", true},
		{"admin", "alice", true}, // owner ⊆ admin
		{"member", "alice", true},
		{"guest", "alice", true},
		{"owner", "bob", false},
		{"admin", "bob", false},
		{"member", "bob", true},
		{"guest", "bob", true},
		{"member", "carol", false},
	}
	for _, c := range cases {
		got, err := e.Check(context.Background(), "p", "", "workspace", "w1", c.rel, c.user, nil)
		if err != nil {
			t.Fatalf("Check %s@%s: %v", c.rel, c.user, err)
		}
		if got != c.want {
			t.Errorf("Check %s@%s = %v, want %v", c.rel, c.user, got, c.want)
		}
	}
}

func TestCheckNestedGroups(t *testing.T) {
	r := &fakeReader{}
	// all-eng contains the backend group; backend contains dana.
	r.add("group", "all-eng", "member", set("group", "backend", "member"))
	r.add("group", "backend", "member", user("dana"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "", "group", "all-eng", "member", "dana", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dana should be a transitive member of all-eng")
	}
	ok, _ = e.Check(context.Background(), "p", "", "group", "all-eng", "member", "ed", nil)
	if ok {
		t.Fatal("ed should not be a member")
	}
}

func TestCheckResourceParentInheritance(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "member", user("bob"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "", "resource", "doc1", "viewer", "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("bob should inherit viewer from parent workspace membership")
	}
}

func TestCheckCycleTerminates(t *testing.T) {
	r := &fakeReader{}
	// a#member@b#member and b#member@a#member — a cycle.
	r.add("group", "a", "member", set("group", "b", "member"))
	r.add("group", "b", "member", set("group", "a", "member"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "", "group", "a", "member", "nobody", nil)
	if err != nil {
		t.Fatalf("cycle should not error: %v", err)
	}
	if ok {
		t.Fatal("no real member; should be false")
	}
}

func TestExpandUnion(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "owner", user("alice"))
	r.add("workspace", "w1", "member", user("bob"))
	e := NewEngine(nil, r)

	tree, err := e.Expand(context.Background(), "p", "", "workspace", "w1", "member", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Union) == 0 {
		t.Fatal("member expansion should be a union node")
	}
}

// TestExpandNodeCap: a tiny node cap makes Expand fail with ErrExpandTooLarge
// instead of materializing an unbounded tree; an unbounded cap (0) succeeds.
func TestExpandNodeCap(t *testing.T) {
	r := &fakeReader{}
	for _, u := range []string{"a", "b", "c", "d", "e", "f"} {
		r.add("workspace", "w1", "owner", user(u))
	}
	e := NewEngine(nil, r)
	if _, err := e.Expand(context.Background(), "p", "", "workspace", "w1", "member", 0); err != nil {
		t.Fatalf("unbounded expand should succeed: %v", err)
	}
	if _, err := e.Expand(context.Background(), "p", "", "workspace", "w1", "member", 2); !errors.Is(err, ErrExpandTooLarge) {
		t.Fatalf("tiny cap should trip ErrExpandTooLarge, got %v", err)
	}
}

// suspendableModel grants effective membership only to members who are not
// suspended: active = member AND NOT suspended. This is the canonical
// exclusion pattern that fixes the cosmetic-SUSPENDED bug.
func suspendableModel() Model {
	return Model{
		"workspace": {
			"member":    this(),
			"suspended": this(),
			"active":    exclusion(computed("member"), computed("suspended")),
		},
	}
}

func TestCheckExclusionSuspendedMember(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "member", user("bob"))
	r.add("workspace", "w1", "member", user("carol"))
	r.add("workspace", "w1", "suspended", user("carol"))
	e := NewEngine(StaticResolver(suspendableModel()), r)

	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "active", "bob", nil); !ok {
		t.Error("bob is a non-suspended member; active should be true")
	}
	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "active", "carol", nil); ok {
		t.Error("carol is suspended; active must be false")
	}
	// The base member grant is untouched by the exclusion.
	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "member", "carol", nil); !ok {
		t.Error("carol remains a member; only active is excluded")
	}
}

// TestSelfReferentialExclusionFailsClosed: a relation whose Exclude branch cycles
// back on itself must DENY (fail closed). Before the negation-polarity fix the
// cycle guard returned false on the exclude branch (excluded=false), so the grant
// leaked through — a self-referential block/suspend that fails OPEN.
func TestSelfReferentialExclusionFailsClosed(t *testing.T) {
	r := &fakeReader{}
	r.add("res", "x", "r", user("u1")) // u1 satisfies the Include leg directly
	m := Model{"res": {
		// r = (direct tuples) AND NOT r  → the Exclude branch is self-referential.
		"r": exclusion(this(), computed("r")),
	}}
	e := NewEngine(StaticResolver(m), r)
	if ok, _ := e.Check(context.Background(), "p", "", "res", "x", "r", "u1", nil); ok {
		t.Error("self-referential exclusion must fail closed (deny), not fan open")
	}
}

// TestNestedExclusionDoubleNegationTerminates: a cycle threaded through two
// exclusion-Exclude branches returns to positive polarity; it must still
// terminate (no infinite recursion, no maxDepth error) and never panic.
func TestNestedExclusionDoubleNegationTerminates(t *testing.T) {
	r := &fakeReader{}
	r.add("res", "x", "base", user("u1"))
	m := Model{"res": {
		"base":  this(),
		"inner": exclusion(computed("base"), computed("a")),
		"a":     exclusion(computed("base"), computed("inner")),
	}}
	e := NewEngine(StaticResolver(m), r)
	if _, err := e.Check(context.Background(), "p", "", "res", "x", "a", "u1", nil); err != nil {
		t.Fatalf("nested exclusion must terminate without error, got %v", err)
	}
}

func TestCheckIntersection(t *testing.T) {
	r := &fakeReader{}
	// enrolled AND paid → can_view.
	r.add("course", "c1", "enrolled", user("amy"))
	r.add("course", "c1", "enrolled", user("ben"))
	r.add("course", "c1", "paid", user("amy"))
	m := Model{"course": {
		"enrolled": this(),
		"paid":     this(),
		"can_view": intersection(computed("enrolled"), computed("paid")),
	}}
	e := NewEngine(StaticResolver(m), r)

	if ok, _ := e.Check(context.Background(), "p", "", "course", "c1", "can_view", "amy", nil); !ok {
		t.Error("amy is enrolled and paid; can_view should be true")
	}
	if ok, _ := e.Check(context.Background(), "p", "", "course", "c1", "can_view", "ben", nil); ok {
		t.Error("ben is enrolled but not paid; can_view must be false")
	}
}

func TestCheckWildcardPublic(t *testing.T) {
	r := &fakeReader{}
	r.add("resource", "pub", "viewer", Subject{Wildcard: true})
	e := NewEngine(nil, r)

	for _, u := range []string{"anyone", "someone-else"} {
		if ok, _ := e.Check(context.Background(), "p", "", "resource", "pub", "viewer", u, nil); !ok {
			t.Errorf("wildcard grant should admit %q", u)
		}
	}
	tree, err := e.Expand(context.Background(), "p", "", "resource", "pub", "viewer", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !treeHasWildcard(tree) {
		t.Error("expand should surface the wildcard leaf")
	}
}

func treeHasWildcard(tr Tree) bool {
	if tr.Wildcard {
		return true
	}
	for _, c := range tr.Union {
		if treeHasWildcard(c) {
			return true
		}
	}
	return false
}

func TestListObjects(t *testing.T) {
	r := &fakeReader{}
	// bob can view c1 (direct), c2 (public wildcard); not c3.
	r.add("resource", "c1", "viewer", user("bob"))
	r.add("resource", "c2", "viewer", Subject{Wildcard: true})
	r.add("resource", "c3", "viewer", user("alice"))
	e := NewEngine(nil, r)

	got, err := e.ListObjects(context.Background(), "p", "", "resource", "viewer", "bob", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"c1": true, "c2": true}
	if len(got) != 2 {
		t.Fatalf("ListObjects = %v, want c1,c2", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected object %q in result", id)
		}
	}
}
