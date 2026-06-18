package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testKeyCollisionSafety pins the driver contract that distinct tuples are
// stored as DISTINCT entries even when their fields differ only in where a
// separator-like character ('/' or '|') falls. The memory driver derives its
// internal key by joining fields, so a naive separator-joined key could alias
// two distinct tuples; this verifies neither aliases the other. Postgres uses
// real composite-key columns and is structurally immune, but the contract must
// hold uniformly across drivers.
func testKeyCollisionSafety(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"

	// Two user tuples whose (object_id, relation) split differs only in the '/'
	// position: "a/b"+"c" vs "a"+"b/c". Distinct tuples must not collide.
	t1 := userTuple("doc", "a/b", "c", "u1")
	t2 := userTuple("doc", "a", "b/c", "u1")
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{t1, t2}, nil); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}
	if subs, err := r.ListSubjects(ctx(), p, "", "doc", "a/b", "c"); err != nil || len(subs) != 1 {
		t.Fatalf("ListSubjects(a/b,c) = %+v err=%v, want exactly one", subs, err)
	}
	if subs, err := r.ListSubjects(ctx(), p, "", "doc", "a", "b/c"); err != nil || len(subs) != 1 {
		t.Fatalf("ListSubjects(a,b/c) = %+v err=%v, want exactly one", subs, err)
	}
	// A '/'-bearing object_id (legitimate, path-like) is still addressable.
	if subs, err := r.ListSubjects(ctx(), p, "", "doc", "a/b", "c"); err != nil || len(subs) != 1 || subs[0].UserID != "u1" {
		t.Fatalf("path-like object_id lookup = %+v err=%v, want u1", subs, err)
	}

	// Subject-set analog: the set components 'namespace/object_id/relation' are
	// joined too. "g/x"+"m" vs "g"+"x/m" must stay distinct subjects on one object.
	ss1 := setTuple("doc", "shared", "viewer", "group", "g/x", "m")
	ss2 := setTuple("doc", "shared", "viewer", "group", "g", "x/m")
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{ss1, ss2}, nil); err != nil {
		t.Fatalf("WriteTuples sets: %v", err)
	}
	subs, err := r.ListSubjects(ctx(), p, "", "doc", "shared", "viewer")
	if err != nil {
		t.Fatalf("ListSubjects sets: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("subject-set collision: got %d subjects, want 2 distinct", len(subs))
	}
	seen := map[string]bool{}
	for _, s := range subs {
		if s.Set == nil {
			t.Fatalf("unexpected non-set subject %+v", s)
		}
		seen[s.Set.ObjectID+"|"+s.Set.Relation] = true
	}
	if !seen["g/x|m"] || !seen["g|x/m"] {
		t.Fatalf("subject sets aliased: seen=%v", seen)
	}

	// '|' (the legacy tuple-key separator) in an object_id must also not alias.
	pipe1 := userTuple("doc", "x|y", "z", "u2")
	pipe2 := userTuple("doc", "x", "y|z", "u2")
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{pipe1, pipe2}, nil); err != nil {
		t.Fatalf("WriteTuples pipe: %v", err)
	}
	if subs, err := r.ListSubjects(ctx(), p, "", "doc", "x|y", "z"); err != nil || len(subs) != 1 {
		t.Fatalf("ListSubjects(x|y,z) = %+v err=%v, want exactly one", subs, err)
	}
	if subs, err := r.ListSubjects(ctx(), p, "", "doc", "x", "y|z"); err != nil || len(subs) != 1 {
		t.Fatalf("ListSubjects(x,y|z) = %+v err=%v, want exactly one", subs, err)
	}
}
