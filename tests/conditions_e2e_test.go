package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	return s
}

// TestConditionGatedCheckOverAPI: a consent-gated and an age-gated grant are
// evaluated against the CheckRequest.context end to end, and an unknown
// condition is rejected at write time.
func TestConditionGatedCheckOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// kid -> viewer on course:c1, conditioned on parental consent.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "c1", Relation: "viewer",
				Subject:       subjUser("kid"),
				ConditionName: "consent_granted",
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	check := func(cc *structpb.Struct) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "course", ObjectId: "c1", Relation: "viewer", SubjectUserId: "kid", Context: cc,
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return got.Msg.Allowed
	}
	if check(nil) {
		t.Fatal("no context: consent-gated grant must deny")
	}
	if check(mustStruct(t, map[string]any{"consent": false})) {
		t.Fatal("consent=false: must deny")
	}
	if !check(mustStruct(t, map[string]any{"consent": true})) {
		t.Fatal("consent=true: must allow")
	}

	// kid -> viewer on course:rated, gated on age >= 13.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "rated", Relation: "viewer",
				Subject:         subjUser("kid"),
				ConditionName:   "age_at_least",
				ConditionParams: mustStruct(t, map[string]any{"min_age": float64(13)}),
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples age: %v", err)
	}
	ageAllows := func(age float64) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "course", ObjectId: "rated", Relation: "viewer", SubjectUserId: "kid",
			Context: mustStruct(t, map[string]any{"age": age}),
		}))
		if err != nil {
			t.Fatalf("Check age: %v", err)
		}
		return got.Msg.Allowed
	}
	if ageAllows(9) {
		t.Fatal("age 9 below band: must deny")
	}
	if !ageAllows(15) {
		t.Fatal("age 15 in band: must allow")
	}

	// An unknown condition is rejected at write time (not silently fail-closed later).
	_, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "x", Relation: "viewer",
				Subject:       subjUser("kid"),
				ConditionName: "no_such_condition",
			},
		}},
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown condition must be rejected at write, got %v", err)
	}
}
