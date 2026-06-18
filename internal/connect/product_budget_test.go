package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// TestProductSurfaceBudgetExhaustion pins that a budget trip on a PRODUCT-surface
// RPC (here GetWorkspace, whose role check goes through Service.requireWorkspace →
// allowed → engine.Check) surfaces as ResourceExhausted — NOT CodeInternal — and
// that the central backstop interceptor counts it on
// authz_eval_backstop_total{reason="budget"} exactly once, just like the
// data-plane surfaces.
func TestProductSurfaceBudgetExhaustion(t *testing.T) {
	ctx := context.Background()
	svc := service.New(memory.New(), nil, nil, service.WithMaxCheckReads(10))
	h := NewHandler(svc, "default", "", "", 100, 0, 0)
	reg := prometheus.NewRegistry()
	h.metrics = newMetrics(reg)

	// A real workspace owned by alice (so the row exists for requireWorkspace).
	createResp, err := h.CreateWorkspace(ctx, connect.NewRequest(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Acme", Slug: "acme",
	}))
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	wsID := createResp.Msg.Workspace.Id

	// A budget-exhausting guest-userset cycle over the workspace's guest relation:
	// guest@workspace:wsID#guest forms a self/loop chain across synthetic objects
	// so a guest check for a non-member poisons the memo and trips the tiny budget.
	const n = 50
	objName := func(i int) string {
		if i == 0 {
			return wsID
		}
		return "ws-budget-" + intName(i)
	}
	updates := make([]*workspacev1.TupleUpdate, 0, n)
	for i := 0; i < n; i++ {
		next := (i + 1) % n
		updates = append(updates, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "workspace", ObjectId: objName(i), Relation: "guest",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "workspace", ObjectId: objName(next), Relation: "guest",
				}}},
			},
		})
	}
	if _, err := h.WriteRelationTuples(ctx, connect.NewRequest(&workspacev1.WriteRelationTuplesRequest{Updates: updates})); err != nil {
		t.Fatalf("write cycle: %v", err)
	}

	// GetWorkspace as a NON-member (bob): the RoleGuest check evaluates the cycle.
	err = runWithBackstops(ctx, h, func(ctx context.Context) error {
		_, e := h.GetWorkspace(ctx, connect.NewRequest(&workspacev1.GetWorkspaceRequest{
			ActingUserId: "bob", WorkspaceId: wsID,
		}))
		return e
	})
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("product-surface budget trip = %v, want ResourceExhausted", err)
	}
	if got := counterValue(t, reg, "authz_eval_backstop_total", map[string]string{"reason": "budget"}); got != 1 {
		t.Fatalf("budget backstop counter = %v, want 1", got)
	}
}
