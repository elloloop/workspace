package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// inheritModel: viewer = this ∪ (viewer of every object under `parent`). This is
// the recursive folder/group shape whose cyclic or wide/deep instances inflate
// per-request reads. (countingReader is defined in nested_folders_extra_test.go;
// its `n` field counts ListSubjects calls — the unit of store work the budget
// bounds.)
func inheritModel() Model {
	return Model{"res": {
		"parent": this(),
		"viewer": union(this(), tupleToUserset("parent", "viewer")),
	}}
}

// TestBudget_CyclicParentChainTrips: a self-referential parent cycle poisons the
// memo (every ancestor recomputes), so reads grow without bound — the budget must
// turn that into ErrEvalBudgetExceeded, not a hang or a silent deny.
func TestBudget_CyclicParentChainTrips(t *testing.T) {
	r := &fakeReader{}
	// A long parent chain o1→o2→…→o200 that LOOPS back to o1. The cycle defeats
	// the memo (a cycle-touched subtree is never cached), so the long chain is
	// traversed at full cost — and the budget stops it well before the end.
	const n = 200
	for i := 1; i <= n; i++ {
		next := i + 1
		if i == n {
			next = 1 // close the loop
		}
		r.add("res", fmt.Sprintf("o%d", i), "parent", set("res", fmt.Sprintf("o%d", next), "viewer"))
	}
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(50)

	_, err := e.Check(context.Background(), "p", "", "res", "o1", "viewer", "nobody", nil)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("cyclic chain: want ErrEvalBudgetExceeded, got %v (reads=%d)", err, cr.n)
	}
	if cr.n > 60 {
		t.Fatalf("reads %d not bounded near budget 50", cr.n)
	}
}

// TestBudget_WideDeepBranchingTrips: a binary tree of parents (each folder has two
// parents) fans out exponentially with depth, blowing the budget.
func TestBudget_WideDeepBranchingTrips(t *testing.T) {
	r := &fakeReader{}
	for n := 1; n <= 4000; n++ {
		r.add("res", fmt.Sprintf("o%d", n), "parent", set("res", fmt.Sprintf("o%d", 2*n), "viewer"))
		r.add("res", fmt.Sprintf("o%d", n), "parent", set("res", fmt.Sprintf("o%d", 2*n+1), "viewer"))
	}
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(500)

	_, err := e.Check(context.Background(), "p", "", "res", "o1", "viewer", "nobody", nil)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("branching graph: want ErrEvalBudgetExceeded, got %v (reads=%d)", err, cr.n)
	}
	if cr.n > 600 {
		t.Fatalf("reads %d not bounded near budget 500", cr.n)
	}
}

// TestBudget_ModerateGraphSucceeds: a legitimate deep-but-linear folder chain
// stays well under a generous budget and succeeds.
func TestBudget_ModerateGraphSucceeds(t *testing.T) {
	r := &fakeReader{}
	for n := 1; n < 20; n++ {
		r.add("res", fmt.Sprintf("o%d", n), "parent", set("res", fmt.Sprintf("o%d", n+1), "viewer"))
	}
	r.add("res", "o20", "viewer", user("alice"))
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(5000)

	ok, err := e.Check(context.Background(), "p", "", "res", "o1", "viewer", "alice", nil)
	if err != nil {
		t.Fatalf("moderate chain: unexpected err %v", err)
	}
	if !ok {
		t.Fatal("alice should inherit viewer down the chain")
	}
	if cr.n > 100 {
		t.Fatalf("moderate chain used %d reads — far more than expected for depth 20", cr.n)
	}
}

// TestBudget_ListObjectsSharesOneBudget: ListObjects over many candidates must
// share a SINGLE budget across the whole operation, so it fails fast rather than
// doing N×budget reads. A per-candidate budget would let the run reach
// ~N×(reads/candidate); the shared budget stops it near the budget.
func TestBudget_ListObjectsSharesOneBudget(t *testing.T) {
	r := &fakeReader{}
	for i := 0; i < 100; i++ {
		o := fmt.Sprintf("o%d", i)
		r.add("res", o, "parent", set("res", o+"p", "viewer"))
		r.add("res", o+"p", "parent", set("res", o+"pp", "viewer"))
	}
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(150)

	_, err := e.ListObjects(context.Background(), "p", "", "res", "viewer", "nobody", 0)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("ListObjects: want shared-budget ErrEvalBudgetExceeded, got %v (reads=%d)", err, cr.n)
	}
	if cr.n > 200 {
		t.Fatalf("ListObjects reads %d not bounded by shared budget 150", cr.n)
	}
}

// TestBackstop_DepthAndCycleSurfaced: an over-deep cyclic graph (ample budget)
// fails closed gracefully (no error) AND records the cycle backstop on the
// context collector — the signal the connect layer turns into a metric.
func TestBackstop_DepthAndCycleSurfaced(t *testing.T) {
	r := &fakeReader{}
	r.add("res", "a", "parent", set("res", "b", "viewer"))
	r.add("res", "b", "parent", set("res", "a", "viewer"))
	e := NewEngine(StaticResolver(inheritModel()), r) // unbounded budget

	ctx, bs := WithBackstops(context.Background())
	ok, err := e.Check(ctx, "p", "", "res", "a", "viewer", "nobody", nil)
	if err != nil {
		t.Fatalf("cyclic graph with ample budget must not error, got %v", err)
	}
	if ok {
		t.Fatal("nobody has a grant; expected graceful deny")
	}
	if bs.Cycle == 0 {
		t.Fatalf("expected a cycle backstop to be recorded, got %+v", bs)
	}
}

// TestBackstop_BudgetSurfaced: the budget backstop is recorded on the context
// when ErrEvalBudgetExceeded fires.
func TestBackstop_BudgetSurfaced(t *testing.T) {
	r := &fakeReader{}
	for i := 1; i <= 50; i++ {
		next := i + 1
		if i == 50 {
			next = 1
		}
		r.add("res", fmt.Sprintf("o%d", i), "parent", set("res", fmt.Sprintf("o%d", next), "viewer"))
	}
	e := NewEngine(StaticResolver(inheritModel()), r).WithMaxReads(10)

	ctx, bs := WithBackstops(context.Background())
	_, err := e.Check(ctx, "p", "", "res", "o1", "viewer", "nobody", nil)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("want ErrEvalBudgetExceeded, got %v", err)
	}
	if bs.Budget == 0 {
		t.Fatalf("expected a budget backstop to be recorded, got %+v", bs)
	}
}
