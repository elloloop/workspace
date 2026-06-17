package tests

import (
	"context"
	"testing"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestScopedIntegrationDelegation: an integration principal (svc:slack) is
// granted a relation on a resource CARRYING a scope_in + not_after condition, so
// its authority is constrained per request — it may act only within its allowed
// scopes and only before its delegation expires. The same object denies an
// out-of-scope action, proving "Slack may read tasks but not change membership".
func TestScopedIntegrationDelegation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// svc:slack -> editor on resource:doc1, scoped to tasks:read|tasks:write.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "doc1", Relation: "editor",
				Subject:         subjUser("svc:slack"),
				ConditionName:   "scope_in",
				ConditionParams: mustStruct(t, map[string]any{"allowed": []any{"tasks:read", "tasks:write"}}),
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples scoped: %v", err)
	}

	editor := func(cc map[string]any) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "doc1", Relation: "editor", SubjectUserId: "svc:slack",
			Context: mustStruct(t, cc),
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return got.Msg.Allowed
	}

	if !editor(map[string]any{"scope": "tasks:read"}) {
		t.Fatal("in-scope (tasks:read): integration must be allowed")
	}
	if !editor(map[string]any{"scope": "tasks:write"}) {
		t.Fatal("in-scope (tasks:write): integration must be allowed")
	}
	if editor(map[string]any{"scope": "membership:write"}) {
		t.Fatal("out-of-scope (membership:write): integration must be DENIED")
	}
	// No scope in context at all → fail closed.
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "doc1", Relation: "editor", SubjectUserId: "svc:slack",
	}))
	if err != nil {
		t.Fatalf("Check no-context: %v", err)
	}
	if got.Msg.Allowed {
		t.Fatal("no scope context: scoped grant must fail closed")
	}
}

// TestTimeBoxedDelegation: an on-behalf-of grant expires via not_after, so the
// delegation lapses automatically without revoking the tuple.
func TestTimeBoxedDelegation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "doc2", Relation: "viewer",
				Subject:         subjUser("svc:linear"),
				ConditionName:   "not_after",
				ConditionParams: mustStruct(t, map[string]any{"until": "2026-07-01T00:00:00Z"}),
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples time-boxed: %v", err)
	}

	viewerAt := func(now string) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "doc2", Relation: "viewer", SubjectUserId: "svc:linear",
			Context: mustStruct(t, map[string]any{"now": now}),
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return got.Msg.Allowed
	}
	if !viewerAt("2026-06-20T00:00:00Z") {
		t.Fatal("within delegation window: must allow")
	}
	if viewerAt("2026-08-01T00:00:00Z") {
		t.Fatal("past delegation expiry: must deny")
	}
}
