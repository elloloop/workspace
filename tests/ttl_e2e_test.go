package tests

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestTupleExpiryOverAPI: a future-dated grant allows, an expired grant denies,
// end to end through the proto -> store -> engine path.
func TestTupleExpiryOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	future := timestamppb.New(time.Now().Add(time.Hour))
	past := timestamppb.New(time.Now().Add(-time.Hour))
	mk := func(user string, exp *timestamppb.Timestamp) *workspacev1.TupleUpdate {
		return &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject:   &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: user}},
				ExpiresAt: exp,
			},
		}
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{mk("live", future), mk("dead", past)},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	if !checkAllowed(ctx, t, h, "doc", "d1", "viewer", "live") {
		t.Fatal("future-dated grant should allow")
	}
	if checkAllowed(ctx, t, h, "doc", "d1", "viewer", "dead") {
		t.Fatal("expired grant must deny (read-time expiry filter)")
	}

	// Re-grant the expired user with a future expiry → access restored.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{mk("dead", future)},
	})); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if !checkAllowed(ctx, t, h, "doc", "d1", "viewer", "dead") {
		t.Fatal("re-granted future expiry should allow")
	}
}
