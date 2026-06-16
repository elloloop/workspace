package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testConditions pins that a grant's optional condition round-trips through the
// store and that the condition is METADATA, not identity: re-writing the same
// tuple replaces (or clears) its condition rather than creating a new row.
func testConditions(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"

	tup := authz.Tuple{
		Namespace: "course", ObjectID: "c1", Relation: "viewer",
		Subject: authz.Subject{
			UserID:    "kid",
			Condition: &authz.Condition{Name: "age_at_least", Params: map[string]any{"min_age": float64(13)}},
		},
	}
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}

	got, err := r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "course", ObjectID: "c1"})
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 tuple, got %d", len(got))
	}
	c := got[0].Subject.Condition
	if c == nil || c.Name != "age_at_least" {
		t.Fatalf("condition not round-tripped: %+v", c)
	}
	if mn, _ := c.Params["min_age"].(float64); mn != 13 {
		t.Fatalf("min_age = %v, want 13", c.Params["min_age"])
	}

	// Re-writing the same tuple replaces the condition (not part of identity).
	tup.Subject.Condition = &authz.Condition{Name: "consent_granted"}
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("re-write: %v", err)
	}
	got, _ = r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "course", ObjectID: "c1"})
	if len(got) != 1 {
		t.Fatalf("re-write changed identity: %d tuples", len(got))
	}
	if rc := got[0].Subject.Condition; rc == nil || rc.Name != "consent_granted" {
		t.Fatalf("condition not replaced on re-write: %+v", rc)
	}

	// Clearing the condition (re-write with none) makes the grant unconditional.
	tup.Subject.Condition = nil
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, _ = r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "course", ObjectID: "c1"})
	if len(got) != 1 || got[0].Subject.Condition != nil {
		t.Fatalf("condition not cleared on re-write: %+v", got[0].Subject.Condition)
	}
}
