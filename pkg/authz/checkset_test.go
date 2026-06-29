package authz

import (
	"context"
	"testing"
)

func ss(ns, obj, rel string) SubjectSet {
	return SubjectSet{Namespace: ns, ObjectID: obj, Relation: rel}
}

// TestCheckSetDirectAndMember covers the two ways a userset query is satisfied:
// structural inclusion (the exact set is stored under the relation) and member
// intersection (a concrete member of the queried set has the relation).
func TestCheckSetDirectAndMember(t *testing.T) {
	r := &fakeReader{}
	// doc1#viewer is granted to the userset group:eng#member, whose member is alice.
	r.add("doc", "doc1", "viewer", set("group", "eng", "member"))
	r.add("group", "eng", "member", user("alice"))
	// doc2#viewer is granted to the concrete user bob; bob is in group:sales.
	r.add("doc", "doc2", "viewer", user("bob"))
	r.add("group", "sales", "member", user("bob"))
	m := Model{"doc": {"viewer": this()}, "group": {"member": this()}}
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()

	cases := []struct {
		name  string
		obj   string
		query SubjectSet
		want  bool
	}{
		{"structural exact match", "doc1", ss("group", "eng", "member"), true},
		{"member intersection (concrete grant)", "doc2", ss("group", "sales", "member"), true},
		{"no match: unrelated set, no members in common", "doc1", ss("group", "sales", "member"), false},
		{"no match: empty/unknown set", "doc2", ss("group", "eng", "member"), false},
	}
	for _, c := range cases {
		got, err := e.CheckSet(ctx, "p", "", "doc", c.obj, "viewer", c.query, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: CheckSet = %v, want %v", c.name, got, c.want)
		}
	}

	// The concrete-user path is unchanged.
	if ok, _ := e.Check(ctx, "p", "", "doc", "doc1", "viewer", "alice", nil); !ok {
		t.Error("concrete-user Check regressed: alice should have viewer on doc1")
	}
	if ok, _ := e.Check(ctx, "p", "", "doc", "doc1", "viewer", "carol", nil); ok {
		t.Error("concrete-user Check regressed: carol should not have viewer on doc1")
	}
}

// TestCheckSetNestedGroup: a query set matches structurally even when it is
// nested inside the stored set (group:all#member contains group:eng#member).
func TestCheckSetNestedGroup(t *testing.T) {
	r := &fakeReader{}
	r.add("doc", "doc1", "viewer", set("group", "all", "member"))
	r.add("group", "all", "member", set("group", "eng", "member")) // nested group
	r.add("group", "eng", "member", user("alice"))
	m := Model{"doc": {"viewer": this()}, "group": {"member": this()}}
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()

	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "viewer", ss("group", "eng", "member"), nil); err != nil || !ok {
		t.Fatalf("nested-group set should match: ok=%v err=%v", ok, err)
	}
	// And via a concrete member of the nested group.
	if ok, _ := e.Check(ctx, "p", "", "doc", "doc1", "viewer", "alice", nil); !ok {
		t.Error("alice (nested member) should have viewer on doc1")
	}
}

// TestCheckSetExclusionSound: the member path must give the sound answer when
// the target relation excludes some members — a set whose only member is
// excluded does NOT have access, even though it is structurally "in" the
// include side.
func TestCheckSetExclusionSound(t *testing.T) {
	r := &fakeReader{}
	// active = viewer AND NOT banned.
	m := Model{
		"doc": {
			"viewer": this(),
			"banned": this(),
			"active": exclusion(computed("viewer"), computed("banned")),
		},
		"group": {"member": this()},
	}
	// group g grants viewer; alice is in g and is banned; bob is in g, not banned.
	r.add("doc", "doc1", "viewer", set("group", "g", "member"))
	r.add("group", "g", "member", user("alice"))
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()

	// Only alice in g, and alice is banned → set g has NO active access.
	r.add("doc", "doc1", "banned", user("alice"))
	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "active", ss("group", "g", "member"), nil); err != nil || ok {
		t.Fatalf("excluded-only set must NOT have active: ok=%v err=%v", ok, err)
	}

	// Add bob (not banned) to g → now the set intersects active via bob.
	r.add("group", "g", "member", user("bob"))
	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "active", ss("group", "g", "member"), nil); err != nil || !ok {
		t.Fatalf("set with a non-excluded member must have active: ok=%v err=%v", ok, err)
	}
}

// TestCheckSetEvaluatesConditions: a CONDITIONAL grant reached via a userset
// query honors the request context exactly as the concrete-user Check path does
// (in-scope allows, out-of-scope/missing-context denies) — Check and CheckSet
// stay in lockstep, so a conditioned grant cannot be bypassed by querying as a
// set instead of a user.
func TestCheckSetEvaluatesConditions(t *testing.T) {
	r := &fakeReader{}
	// group:eng#member = alice; doc1#editor granted to alice, gated by scope_in.
	r.add("group", "eng", "member", user("alice"))
	r.add("doc", "doc1", "editor", Subject{
		UserID:    "alice",
		Condition: &Condition{Name: "scope_in", Params: map[string]any{"allowed": []any{"tasks:read"}}},
	})
	m := Model{"doc": {"editor": this()}, "group": {"member": this()}}
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()
	q := ss("group", "eng", "member")

	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "editor", q, map[string]any{"scope": "tasks:read"}); err != nil || !ok {
		t.Fatalf("in-scope set query must allow the conditioned grant: ok=%v err=%v", ok, err)
	}
	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "editor", q, map[string]any{"scope": "membership:write"}); err != nil || ok {
		t.Fatalf("out-of-scope set query must be denied: ok=%v err=%v", ok, err)
	}
	if ok, err := e.CheckSet(ctx, "p", "", "doc", "doc1", "editor", q, nil); err != nil || ok {
		t.Fatalf("missing-context set query must fail closed: ok=%v err=%v", ok, err)
	}
}

// TestCheckSetIntersectionMembers: a query set whose relation is an INTERSECTION
// resolves to only the members present in EVERY operand, exercising the engine's
// member-intersection resolution (membersOfTree intersection branch +
// intersectUsers) — so a CheckSet over an intersection-defined set is sound.
func TestCheckSetIntersectionMembers(t *testing.T) {
	// eligible = member AND verified.
	m := Model{
		"group": {
			"member":   this(),
			"verified": this(),
			"eligible": intersection(computed("member"), computed("verified")),
		},
		"doc": {"viewer": this()},
	}
	ctx := context.Background()
	q := ss("group", "g", "eligible")

	// alice is member AND verified (eligible); bob is member only; carol verified only.
	base := func() *fakeReader {
		r := &fakeReader{}
		r.add("group", "g", "member", user("alice"))
		r.add("group", "g", "member", user("bob"))
		r.add("group", "g", "verified", user("alice"))
		r.add("group", "g", "verified", user("carol"))
		return r
	}

	// Target grants viewer to alice (who IS in the intersection) → the set matches.
	rPos := base()
	rPos.add("doc", "d1", "viewer", user("alice"))
	if ok, err := NewEngine(StaticResolver(m), rPos).CheckSet(ctx, "p", "", "doc", "d1", "viewer", q, nil); err != nil || !ok {
		t.Fatalf("eligible set (contains alice) must have viewer: ok=%v err=%v", ok, err)
	}

	// Target grants viewer only to bob — member but NOT verified, so NOT eligible →
	// the intersection excludes bob and the set must not match.
	rNeg := base()
	rNeg.add("doc", "d2", "viewer", user("bob"))
	if ok, err := NewEngine(StaticResolver(m), rNeg).CheckSet(ctx, "p", "", "doc", "d2", "viewer", q, nil); err != nil || ok {
		t.Fatalf("eligible excludes bob (not verified); set must NOT have viewer: ok=%v err=%v", ok, err)
	}
}

// TestCheckSetPublicTarget: a public (wildcard) grant is matched by any
// non-empty set query.
func TestCheckSetPublicTarget(t *testing.T) {
	r := &fakeReader{}
	r.add("doc", "pub", "viewer", Subject{Wildcard: true})
	r.add("group", "eng", "member", user("alice"))
	m := Model{"doc": {"viewer": this()}, "group": {"member": this()}}
	e := NewEngine(StaticResolver(m), r)
	if ok, err := e.CheckSet(context.Background(), "p", "", "doc", "pub", "viewer", ss("group", "eng", "member"), nil); err != nil || !ok {
		t.Fatalf("public target should admit any set: ok=%v err=%v", ok, err)
	}
}
