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

func (f *fakeReader) ListSubjects(_ context.Context, _, ns, obj, rel string) ([]Subject, error) {
	var out []Subject
	for _, t := range f.tuples {
		if t.Namespace == ns && t.ObjectID == obj && t.Relation == rel {
			out = append(out, t.Subject)
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
	e := NewEngine(DefaultModel(), r)

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
		got, err := e.Check(context.Background(), "p", "workspace", "w1", c.rel, c.user)
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

	ok, err := e.Check(context.Background(), "p", "group", "all-eng", "member", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dana should be a transitive member of all-eng")
	}
	ok, _ = e.Check(context.Background(), "p", "group", "all-eng", "member", "ed")
	if ok {
		t.Fatal("ed should not be a member")
	}
}

func TestCheckResourceParentInheritance(t *testing.T) {
	r := &fakeReader{}
	r.add("workspace", "w1", "member", user("bob"))
	r.add("resource", "doc1", "parent", set("workspace", "w1", "member"))
	e := NewEngine(nil, r)

	ok, err := e.Check(context.Background(), "p", "resource", "doc1", "viewer", "bob")
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

	ok, err := e.Check(context.Background(), "p", "group", "a", "member", "nobody")
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

	tree, err := e.Expand(context.Background(), "p", "workspace", "w1", "member")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Union) == 0 {
		t.Fatal("member expansion should be a union node")
	}
}
