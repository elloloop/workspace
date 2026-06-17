package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestComputedOnlyWriteRejectedOverAPI: WriteRelationTuples rejects an insert on
// a computed-only relation (workspace#editor in DefaultModel) with
// InvalidArgument, while a writable relation and a delete succeed.
func TestComputedOnlyWriteRejectedOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	write := func(op workspacev1.TupleUpdate_Op, ns, rel string) error {
		_, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
			Updates: []*workspacev1.TupleUpdate{{
				Op: op,
				Tuple: &workspacev1.RelationTuple{
					Namespace: ns, ObjectId: "o1", Relation: rel,
					Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "u1"}},
				},
			}},
		}))
		return err
	}

	// Insert on a computed-only relation → InvalidArgument.
	if err := write(workspacev1.TupleUpdate_OP_INSERT, "workspace", "editor"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("insert workspace#editor = %v, want InvalidArgument", err)
	}
	// Insert on a writable relation → OK.
	if err := write(workspacev1.TupleUpdate_OP_INSERT, "workspace", "admin"); err != nil {
		t.Fatalf("insert workspace#admin should be allowed, got %v", err)
	}
	// Delete on a computed-only relation → lenient (OK).
	if err := write(workspacev1.TupleUpdate_OP_DELETE, "workspace", "editor"); err != nil {
		t.Fatalf("delete workspace#editor should be lenient, got %v", err)
	}
}

// TestComputedOnlyWriteRejectsWholeBatch: a multi-op batch containing a
// computed-only INSERT is rejected ATOMICALLY — a valid INSERT in the same
// batch does NOT land (validation happens before any store write).
func TestComputedOnlyWriteRejectsWholeBatch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tuple := func(rel, user string) *workspacev1.RelationTuple {
		return &workspacev1.RelationTuple{
			Namespace: "workspace", ObjectId: "wb", Relation: rel,
			Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: user}},
		}
	}
	ins := func(rel, user string) *workspacev1.TupleUpdate {
		return &workspacev1.TupleUpdate{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: tuple(rel, user)}
	}

	landed := func() bool {
		resp, err := h.authz.ReadRelationTuples(ctx, req(&workspacev1.ReadRelationTuplesRequest{
			Namespace: "workspace", ObjectId: "wb", Relation: "admin",
		}))
		if err != nil {
			t.Fatalf("ReadRelationTuples: %v", err)
		}
		return len(resp.Msg.Tuples) > 0
	}

	// Valid admin INSERT precedes a computed-only editor INSERT → whole batch rejected.
	_, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{ins("admin", "u1"), ins("editor", "u2")},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("mixed batch = %v, want InvalidArgument", err)
	}
	if landed() {
		t.Fatal("valid INSERT must NOT persist when the batch is rejected (atomicity)")
	}

	// Order-independence: bad op first, same result, still nothing lands.
	_, err = h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{ins("editor", "u2"), ins("admin", "u1")},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("mixed batch (bad first) = %v, want InvalidArgument", err)
	}
	if landed() {
		t.Fatal("valid INSERT must NOT persist regardless of op order")
	}
}
