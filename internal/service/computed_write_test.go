package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// TestWriteTuplesRejectsComputedOnlyRelations: the generic tuple-write path
// refuses an INSERT on a relation the project's model defines as computed-only
// (no `this` leg) — the engine would never read it, so storing it is an inert
// grant. Writable relations, unknown relations, and DELETEs are unaffected.
func TestWriteTuplesRejectsComputedOnlyRelations(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()
	p := service.Principal{ProjectID: "p"}

	ins := func(ns, rel string) error {
		_, err := svc.WriteTuples(ctx, p, []service.TupleOp{
			{Tuple: authz.Tuple{Namespace: ns, ObjectID: "o1", Relation: rel, Subject: authz.Subject{UserID: "u1"}}},
		})
		return err
	}

	// Computed-only relations in DefaultModel → rejected.
	for _, rel := range []string{"editor", "viewer"} {
		if err := ins("workspace", rel); !errors.Is(err, service.ErrInvalidArgument) {
			t.Fatalf("insert workspace#%s = %v, want ErrInvalidArgument", rel, err)
		}
	}

	// Relations with a `this` leg → allowed.
	for _, c := range []struct{ ns, rel string }{
		{"workspace", "owner"},
		{"workspace", "admin"},
		{"workspace", "member"},
		{"resource", "viewer"}, // union(this, ...)
		{"group", "member"},
		{"doc", "viewer"}, // unknown namespace → defaults to `this`
	} {
		if err := ins(c.ns, c.rel); err != nil {
			t.Fatalf("insert %s#%s should be allowed, got %v", c.ns, c.rel, err)
		}
	}

	// DELETE on a computed-only relation is lenient (clean-up path).
	if _, err := svc.WriteTuples(ctx, p, []service.TupleOp{
		{Delete: true, Tuple: authz.Tuple{Namespace: "workspace", ObjectID: "o1", Relation: "editor", Subject: authz.Subject{UserID: "u1"}}},
	}); err != nil {
		t.Fatalf("delete workspace#editor should be lenient, got %v", err)
	}
}

// TestWriteTuplesComputedOnlyPerProjectModel: the rejection follows the PROJECT's
// configured model — a custom computed-only relation is rejected for that
// project, while its writable backing relation is accepted.
func TestWriteTuplesComputedOnlyPerProjectModel(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	// A project whose "course" namespace has a writable `enrolled` (this) and a
	// computed-only `can_view` (= computed("enrolled")).
	model := authz.Model{
		"course": {
			"enrolled": {},                                  // this()
			"can_view": authz.Rewrite{Computed: "enrolled"}, // computed-only
		},
	}
	if _, err := svc.CreateProject(ctx, "edu", "Edu", model, "", 0); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	p := service.Principal{ProjectID: "edu"}

	if _, err := svc.WriteTuples(ctx, p, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "course", ObjectID: "c1", Relation: "can_view", Subject: authz.Subject{UserID: "amy"}}},
	}); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("insert course#can_view (computed-only) = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.WriteTuples(ctx, p, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "course", ObjectID: "c1", Relation: "enrolled", Subject: authz.Subject{UserID: "amy"}}},
	}); err != nil {
		t.Fatalf("insert course#enrolled (writable) should be allowed, got %v", err)
	}

	// The SAME relation name is writable in a DIFFERENT (default-model) project,
	// where "course" is an unknown namespace → defaults to `this`.
	if _, err := svc.WriteTuples(ctx, service.Principal{ProjectID: "other"}, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "course", ObjectID: "c1", Relation: "can_view", Subject: authz.Subject{UserID: "amy"}}},
	}); err != nil {
		t.Fatalf("course#can_view in a default-model project should be writable, got %v", err)
	}
}
