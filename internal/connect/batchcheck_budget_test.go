package connect

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// TestBatchCheckBudgetExhaustionConnect pins the connect-layer contract that a
// per-item read-budget exhaustion is ITEM-SPECIFIC: the RPC returns HTTP 200
// (nil top-level error), the pathological item's slot carries the budget error,
// its sibling resolves correctly, and the budget backstop is counted exactly
// once on authz_eval_backstop_total{reason="budget"} — the alertable signal.
func TestBatchCheckBudgetExhaustionConnect(t *testing.T) {
	ctx := context.Background()
	svc := service.New(memory.New(), nil, nil, service.WithMaxCheckReads(10))
	h := NewHandler(svc, "default", "", "", 100, 0, 0)
	reg := prometheus.NewRegistry()
	h.metrics = newMetrics(reg)

	// A self-referential resource.parent cycle: viewer walks parent→viewer
	// forever, poisoning the memo so reads grow without bound and the tiny
	// budget turns it into ResourceExhausted.
	const chain = 50
	updates := make([]*workspacev1.TupleUpdate, 0, chain+1)
	for i := 1; i <= chain; i++ {
		next := i + 1
		if i == chain {
			next = 1 // close the loop
		}
		updates = append(updates, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: intName(i), Relation: "parent",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "resource", ObjectId: intName(next), Relation: "viewer",
				}}},
			},
		})
	}
	// A trivially-resolvable allow for the sibling item.
	updates = append(updates, &workspacev1.TupleUpdate{
		Op: workspacev1.TupleUpdate_OP_INSERT,
		Tuple: &workspacev1.RelationTuple{
			Namespace: "resource", ObjectId: "ok", Relation: "viewer",
			Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "alice"}},
		},
	})
	if _, err := h.WriteRelationTuples(ctx, connect.NewRequest(&workspacev1.WriteRelationTuplesRequest{Updates: updates})); err != nil {
		t.Fatalf("write: %v", err)
	}

	var resp *connect.Response[workspacev1.BatchCheckResponse]
	err := runWithBackstops(ctx, h, func(ctx context.Context) error {
		var e error
		resp, e = h.BatchCheck(ctx, connect.NewRequest(&workspacev1.BatchCheckRequest{
			Items: []*workspacev1.BatchCheckItem{
				{Namespace: "resource", ObjectId: "o1", Relation: "viewer", SubjectUserId: "nobody"},
				{Namespace: "resource", ObjectId: "ok", Relation: "viewer", SubjectUserId: "alice"},
			},
		}))
		return e
	})
	// (1) The call returns HTTP 200 — a per-item budget hit must not abort it.
	if err != nil {
		t.Fatalf("per-item budget exhaustion must not abort the batch: %v", err)
	}
	results := resp.Msg.Results
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	// (2) The bad item carries the budget error; the sibling is allowed.
	if !strings.Contains(results[0].Error, "budget") {
		t.Fatalf("budget item slot must carry the budget error, got %q", results[0].Error)
	}
	if results[0].Allowed {
		t.Fatal("exhausted item must not be allowed")
	}
	if results[1].Error != "" || !results[1].Allowed {
		t.Fatalf("sibling item must succeed, got %+v", results[1])
	}
	// (3) Exactly one budget backstop counted.
	if got := counterValue(t, reg, "authz_eval_backstop_total", map[string]string{"reason": "budget"}); got != 1 {
		t.Fatalf("budget backstop counter = %v, want 1", got)
	}
}
