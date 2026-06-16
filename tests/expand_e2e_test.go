package tests

import (
	"context"
	"testing"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestExpandSerializesNewNodeTypes pins the proto projection of the authz
// decision-tree node types added in this change: EXCLUSION (two ordered
// children), INTERSECTION (one child per operand), and a wildcard leaf. Without
// this, a refactor of treeToProto that swapped the exclusion children or dropped
// the wildcard flag would ship silently.
func TestExpandSerializesNewNodeTypes(t *testing.T) {
	h := newAdminHarness(t)
	ctx := context.Background()
	const model = `{"doc":{
		"public":{"this":true},
		"blocked":{"this":true},
		"enrolled":{"this":true},
		"paid":{"this":true},
		"published":{"exclusion":{"include":{"computed":"public"},"exclude":{"computed":"blocked"}}},
		"premium":{"intersection":[{"computed":"enrolled"},{"computed":"paid"}]}
	}}`
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "px", Name: "Expand", ModelJson: model,
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// A public wildcard grant so the include leg carries a wildcard leaf.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		ProjectId: "px",
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				ProjectId: "px", Namespace: "doc", ObjectId: "d1", Relation: "public",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Wildcard{Wildcard: true}},
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	expand := func(rel string) *workspacev1.UsersetTree {
		t.Helper()
		resp, err := h.authz.Expand(ctx, req(&workspacev1.ExpandRequest{
			ProjectId: "px", Namespace: "doc", ObjectId: "d1", Relation: rel,
		}))
		if err != nil {
			t.Fatalf("Expand %s: %v", rel, err)
		}
		return resp.Msg.Tree
	}

	pub := expand("public")
	if pub.Type != workspacev1.UsersetTree_NODE_TYPE_LEAF || !pub.Wildcard {
		t.Fatalf("public = type %v wildcard %v, want LEAF + wildcard", pub.Type, pub.Wildcard)
	}

	published := expand("published")
	if published.Type != workspacev1.UsersetTree_NODE_TYPE_EXCLUSION {
		t.Fatalf("published type = %v, want EXCLUSION", published.Type)
	}
	if len(published.Children) != 2 {
		t.Fatalf("EXCLUSION children = %d, want 2 (include, exclude)", len(published.Children))
	}
	// children[0] is the include leg (public) and must carry the wildcard.
	if !published.Children[0].Wildcard {
		t.Fatal("EXCLUSION children[0] (include) should carry the public wildcard")
	}

	premium := expand("premium")
	if premium.Type != workspacev1.UsersetTree_NODE_TYPE_INTERSECTION {
		t.Fatalf("premium type = %v, want INTERSECTION", premium.Type)
	}
	if len(premium.Children) != 2 {
		t.Fatalf("INTERSECTION children = %d, want 2", len(premium.Children))
	}
}
