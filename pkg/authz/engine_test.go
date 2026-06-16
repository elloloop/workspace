package authz

import (
	"context"
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
		got, err := e.Check(context.Background(), "p", "", "workspace", "w1", c.rel, c.user)
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

	ok, err := e.Check(context.Background(), "p", "", "group", "all-eng", "member", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dana should be a transitive member of all-eng")
	}
	ok, _ = e.Check(context.Background(), "p", "", "group", "all-eng", "member", "ed")
	if ok {
		t.Fatal("ed should not be a member")
	}
}

func TestCheckResourceParentInheritance(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "member", user("bob"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "", "resource", "doc1", "viewer", "bob")
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

	ok, err := e.Check(context.Background(), "p", "", "group", "a", "member", "nobody")
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

	tree, err := e.Expand(context.Background(), "p", "", "workspace", "w1", "member")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Union) == 0 {
		t.Fatal("member expansion should be a union node")
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

	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "active", "bob"); !ok {
		t.Error("bob is a non-suspended member; active should be true")
	}
	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "active", "carol"); ok {
		t.Error("carol is suspended; active must be false")
	}
	// The base member grant is untouched by the exclusion.
	if ok, _ := e.Check(context.Background(), "p", "", "workspace", "w1", "member", "carol"); !ok {
		t.Error("carol remains a member; only active is excluded")
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

	if ok, _ := e.Check(context.Background(), "p", "", "course", "c1", "can_view", "amy"); !ok {
		t.Error("amy is enrolled and paid; can_view should be true")
	}
	if ok, _ := e.Check(context.Background(), "p", "", "course", "c1", "can_view", "ben"); ok {
		t.Error("ben is enrolled but not paid; can_view must be false")
	}
}

func TestCheckWildcardPublic(t *testing.T) {
	r := &fakeReader{}
	r.add("resource", "pub", "viewer", Subject{Wildcard: true})
	e := NewEngine(nil, r)

	for _, u := range []string{"anyone", "someone-else"} {
		if ok, _ := e.Check(context.Background(), "p", "", "resource", "pub", "viewer", u); !ok {
			t.Errorf("wildcard grant should admit %q", u)
		}
	}
	tree, err := e.Expand(context.Background(), "p", "", "resource", "pub", "viewer")
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
