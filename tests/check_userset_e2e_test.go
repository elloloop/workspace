package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestCheckUsersetSubjectOverAPI: Check can ask whether a USERSET (a group) has
// a relation, not just a concrete user — and the concrete-user path is
// unchanged.
func TestCheckUsersetSubjectOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	setSubj := func(ns, obj, rel string) *workspacev1.Subject {
		return &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
			Namespace: ns, ObjectId: obj, Relation: rel,
		}}}
	}
	userSubj := func(id string) *workspacev1.Subject {
		return &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: id}}
	}

	// resource:doc1#viewer granted to group:cohort7#member; alice is a member.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{
			{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "doc1", Relation: "viewer", Subject: setSubj("group", "cohort7", "member"),
			}},
			{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{
				Namespace: "group", ObjectId: "cohort7", Relation: "member", Subject: userSubj("alice"),
			}},
		},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	checkSet := func(ns, obj, rel, sns, sobj, srel string) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: ns, ObjectId: obj, Relation: rel,
			SubjectSet: &workspacev1.SubjectSet{Namespace: sns, ObjectId: sobj, Relation: srel},
		}))
		if err != nil {
			t.Fatalf("Check(set): %v", err)
		}
		return got.Msg.Allowed
	}

	// The queried userset has viewer (structural match).
	if !checkSet("resource", "doc1", "viewer", "group", "cohort7", "member") {
		t.Error("group:cohort7#member should have viewer on doc1")
	}
	// A different userset does not.
	if checkSet("resource", "doc1", "viewer", "group", "other", "member") {
		t.Error("group:other#member should NOT have viewer on doc1")
	}

	// The concrete-user path is unchanged.
	if got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "doc1", Relation: "viewer", SubjectUserId: "alice",
	})); err != nil || !got.Msg.Allowed {
		t.Fatalf("concrete-user Check: allowed=%v err=%v (want true)", got.Msg.Allowed, err)
	}

	// Neither subject set → InvalidArgument.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "doc1", Relation: "viewer",
	})); err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument with no subject, got %v", err)
	}
	// Both subjects → InvalidArgument.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "doc1", Relation: "viewer", SubjectUserId: "alice",
		SubjectSet: &workspacev1.SubjectSet{Namespace: "group", ObjectId: "cohort7", Relation: "member"},
	})); err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument with both subjects, got %v", err)
	}
}
