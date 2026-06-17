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
