package tests

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/workspaceserver"
)

// TestBatchCheckOverAPI: BatchCheck results are index-aligned to items and
// match what N individual Check calls would return; an invalid item fails only
// its own slot.
func TestBatchCheckOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// alice owns w1 (owner ⊃ member); bob has nothing.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op:    workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{Namespace: "workspace", ObjectId: "w1", Relation: "owner", Subject: subjUser("alice")},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	items := []*workspacev1.BatchCheckItem{
		{Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: "alice"},  // true
		{Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "alice"}, // true (owner ⊃ member)
		{Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: "bob"},    // false
		{Namespace: "workspace", ObjectId: "w1", Relation: "", SubjectUserId: "alice"},       // invalid → error slot
	}
	resp, err := h.authz.BatchCheck(ctx, req(&workspacev1.BatchCheckRequest{Items: items}))
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	got := resp.Msg.Results
	if len(got) != len(items) {
		t.Fatalf("results = %d, want %d (index-aligned)", len(got), len(items))
	}
	if !got[0].Allowed || got[0].Error != "" {
		t.Fatalf("item 0 = %+v, want allowed", got[0])
	}
	if !got[1].Allowed {
		t.Fatalf("item 1 (owner⊃member) = %+v, want allowed", got[1])
	}
	if got[2].Allowed || got[2].Error != "" {
		t.Fatalf("item 2 = %+v, want denied", got[2])
	}
	if got[3].Error == "" || got[3].Allowed {
		t.Fatalf("item 3 (invalid) = %+v, want isolated error", got[3])
	}

	// Each batch result equals the standalone Check for the same question.
	for i, it := range items[:3] {
		single, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: it.Namespace, ObjectId: it.ObjectId, Relation: it.Relation, SubjectUserId: it.SubjectUserId,
		}))
		if err != nil {
			t.Fatalf("Check item %d: %v", i, err)
		}
		if single.Msg.Allowed != got[i].Allowed {
			t.Fatalf("item %d: batch=%v single=%v", i, got[i].Allowed, single.Msg.Allowed)
		}
	}
}

// TestBatchCheckCap: a batch larger than the configured max is rejected.
func TestBatchCheckCap(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:   "default",
			ServiceAuthTokens:  []string{svcToken},
			MaxBatchCheckItems: 2,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)

	item := &workspacev1.BatchCheckItem{Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: "a"}
	_, err = authz.BatchCheck(context.Background(), req(&workspacev1.BatchCheckRequest{
		Items: []*workspacev1.BatchCheckItem{item, item, item},
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument over cap, got %v", err)
	}
}
