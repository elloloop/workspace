package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestBudget_ExpandFullCapDeepTreeSucceeds: a LEGITIMATE acyclic Expand whose
// read count sits BETWEEN the flat single-Check budget (DefaultMaxCheckReads =
// 5000) and the node cap (DefaultMaxExpandNodes = 10000) must SUCCEED at the
// production defaults. Expand is bounded by the node cap, not the flat budget;
// seeding its read budget off the node cap (expandBudget) is what lets it pass.
// Before that fix the flat 5000 budget tripped first and wrongly returned
// ErrEvalBudgetExceeded for this legitimate tree.
func TestBudget_ExpandFullCapDeepTreeSucceeds(t *testing.T) {
	// A WIDE (not deep — recursion is capped at maxRecursionDepth=32) acyclic
	// tree: viewer = tupleToUserset(parent, leaf), so expanding viewer on the
	// root reads its parent tupleset once and then expands the leaf relation on
	// every referenced object (depth 1). Each leaf costs one read and one node,
	// so N leaves produce ~N reads and ~N nodes: at N=6000 the read count (6001)
	// sits ABOVE the flat single-Check budget (5000) yet BELOW the node cap
	// (10000). The fully acyclic tree must come back whole.
	m := Model{"res": {
		"parent": this(),
		"leaf":   this(),
		"viewer": tupleToUserset("parent", "leaf"),
	}}
	r := &fakeReader{}
	const n = 6000
	for i := 0; i < n; i++ {
		r.add("res", "root", "parent", set("res", fmt.Sprintf("leaf%d", i), "leaf"))
	}
	cr := &countingReader{fakeReader: r}
	// Production defaults: maxReads=5000, maxNodes=10000.
	e := NewEngine(StaticResolver(m), cr).WithMaxReads(5000)

	tree, err := e.Expand(context.Background(), "p", "", "res", "root", "viewer", 10000)
	if err != nil {
		t.Fatalf("legit full-cap wide Expand must succeed, got %v (reads=%d)", err, cr.n)
	}
	if cr.n <= 5000 {
		t.Fatalf("fixture must read MORE than the flat budget to prove the over-trip is fixed, reads=%d", cr.n)
	}
	if tree.Expanded.ObjectID != "root" {
		t.Fatalf("expected the root tree, got %+v", tree.Expanded)
	}
}

// TestBudget_ExpandPathologicalTrips: a cyclic/branching graph drives Expand's
// reads past even the node-cap-scaled budget, so it returns
// ErrEvalBudgetExceeded AND records a Budget backstop. The cap is sized so the
// pathological scan exceeds the scaled budget (expandBudget = maxNodes × 2).
func TestBudget_ExpandPathologicalTrips(t *testing.T) {
	r := &fakeReader{}
	// A binary parent tree: each object has two parents, fanning out
	// exponentially with depth. The expand walks every branch (no memo across
	// the tree shape for distinct objects), exhausting the budget fast.
	for n := 1; n <= 8000; n++ {
		r.add("res", fmt.Sprintf("o%d", n), "parent", set("res", fmt.Sprintf("o%d", 2*n), "viewer"))
		r.add("res", fmt.Sprintf("o%d", n), "parent", set("res", fmt.Sprintf("o%d", 2*n+1), "viewer"))
	}
	cr := &countingReader{fakeReader: r}
	// Node cap DISABLED (non-positive) so the read budget is the sole bound:
	// expandBudget collapses to the flat maxReads (200) when there is no node cap
	// to scale off. The branching scan blows past 200 reads and trips the budget
	// — proving the read budget still bites on a genuinely pathological model
	// even when the node cap is not the limiter.
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(200)

	ctx, bs := WithBackstops(context.Background())
	_, err := e.Expand(ctx, "p", "", "res", "o1", "viewer", 0)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("pathological Expand: want ErrEvalBudgetExceeded, got %v (reads=%d)", err, cr.n)
	}
	if bs.Budget == 0 {
		t.Fatalf("expected a budget backstop to be recorded, got %+v", bs)
	}
}
