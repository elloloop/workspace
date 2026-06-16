package authz

import (
	"context"
	"testing"
)

// TestWildcardInsideExclusion pins the security-critical interaction the commit
// is built on: a public (user:*) grant wrapped in an exclusion must still deny a
// blocked user — the wildcard short-circuit in evalThis is only safe because the
// exclusion is evaluated one rewrite layer up.
func TestWildcardInsideExclusion(t *testing.T) {
	r := &fakeReader{}
	r.add("doc", "d1", "public", Subject{Wildcard: true})
	r.add("doc", "d1", "blocked", user("bob"))
	m := Model{"doc": {
		"public":    this(),
		"blocked":   this(),
		"published": exclusion(computed("public"), computed("blocked")),
	}}
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()

	if ok, _ := e.Check(ctx, "p", "", "doc", "d1", "published", "alice", nil); !ok {
		t.Error("non-blocked user must see published wildcard content")
	}
	if ok, _ := e.Check(ctx, "p", "", "doc", "d1", "published", "bob", nil); ok {
		t.Error("blocked user must be DENIED published wildcard content (exclusion over wildcard)")
	}
}

// TestWildcardInsideIntersection: a public wildcard leg does not satisfy a
// sibling 'paid' requirement — a wildcard must not admit an unpaid user.
func TestWildcardInsideIntersection(t *testing.T) {
	r := &fakeReader{}
	r.add("doc", "d1", "public", Subject{Wildcard: true})
	r.add("doc", "d1", "paid", user("amy"))
	m := Model{"doc": {
		"public":  this(),
		"paid":    this(),
		"premium": intersection(computed("public"), computed("paid")),
	}}
	e := NewEngine(StaticResolver(m), r)
	ctx := context.Background()

	if ok, _ := e.Check(ctx, "p", "", "doc", "d1", "premium", "amy", nil); !ok {
		t.Error("paid user must pass the wildcard AND paid intersection")
	}
	if ok, _ := e.Check(ctx, "p", "", "doc", "d1", "premium", "ben", nil); ok {
		t.Error("unpaid user must be denied despite the public wildcard leg")
	}
}
