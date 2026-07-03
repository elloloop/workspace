package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestConsistencyTokenForeignShardRejected: a token issued for one (project,
// tenant) cannot be used on another shard.
func TestConsistencyTokenForeignShardRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	wrote, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		TenantId: "tenant-a",
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "amy"}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Using tenant-a's token on tenant-b is rejected.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
		TenantId: "tenant-b", AtLeastConsistencyToken: wrote.Msg.ConsistencyToken,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("foreign-shard token: want InvalidArgument, got %v", err)
	}
}
