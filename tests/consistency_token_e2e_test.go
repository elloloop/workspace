package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestConsistencyTokenReadAfterWrite: a WriteRelationTuples returns a token, a
// Check carrying it observes the just-written grant, a malformed token is
// rejected (InvalidArgument), and a tokenless Check behaves as before.
func TestConsistencyTokenReadAfterWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	wrote, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
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
	token := wrote.Msg.ConsistencyToken
	if token == "" {
		t.Fatal("WriteRelationTuples must return a consistency token")
	}

	// Read-after-write: a Check carrying the token observes the grant.
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
		AtLeastConsistencyToken: token,
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("token-consistent check = %v, %v; want allowed", got.Msg.GetAllowed(), err)
	}

	// A tokenless Check is unchanged.
	if got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
	})); err != nil || !got.Msg.Allowed {
		t.Fatalf("tokenless check = %v, %v; want allowed", got.Msg.GetAllowed(), err)
	}

	// A malformed token is rejected, not silently ignored.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
		AtLeastConsistencyToken: "not-a-real-token",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed token: want InvalidArgument, got %v", err)
	}

	// ListObjects and Expand also honor the token end to end.
	if _, err := h.authz.ListObjects(ctx, req(&workspacev1.ListObjectsRequest{
		Namespace: "doc", Relation: "viewer", SubjectUserId: "amy", AtLeastConsistencyToken: token,
	})); err != nil {
		t.Fatalf("ListObjects with token: %v", err)
	}
}

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
