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
// share a SINGLE budget across the whole operation, so a genuinely pathological
// graph fails fast rather than doing N×budget reads. The fan-out budget scales
// with the candidate cap (cap × maxDepth × headroom), so the abusive fixture is
// sized to exceed it: many candidates each rooted in a deep CYCLIC parent chain
// (the cycle poisons the memo, so every candidate pays full chain cost).
func TestBudget_ListObjectsSharesOneBudget(t *testing.T) {
	r := &fakeReader{}
	// 50 independent candidates, each a 50-long parent chain that loops back to
	// itself. cap=50 → fan-out budget ≈ 50×32×2 = 3200; the cyclic scan does far
	// more (≈50 candidates × ~50 chain) and trips it.
	const cands, chain = 50, 50
	for c := 0; c < cands; c++ {
		for i := 0; i < chain; i++ {
			next := (i + 1) % chain
			o := fmt.Sprintf("c%d_o%d", c, i)
			nxt := fmt.Sprintf("c%d_o%d", c, next)
			r.add("res", o, "parent", set("res", nxt, "viewer"))
		}
	}
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(150)

	// cap the candidate set at the realized size so the fan-out budget is sized
	// from the cap, then assert the pathological scan trips it.
	_, err := e.ListObjects(context.Background(), "p", "", "res", "viewer", "nobody", cands*chain)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("ListObjects: want shared-budget ErrEvalBudgetExceeded, got %v (reads=%d)", err, cr.n)
	}
}

// TestBudget_ListObjectsFullCapDeepScanSucceeds: a LEGITIMATE ListObjects at the
// PRODUCTION defaults — single-Check budget DefaultMaxCheckReads, candidate cap
// DefaultMaxListObjects — over a deep (10+) inheritance hierarchy with ~900
// candidates must SUCCEED and return the full matching list. The flat
// single-Check budget (5000) is far below this scan's legitimate worst case
// (~900 candidates × depth); the scaled fan-out budget is what lets it pass.
func TestBudget_ListObjectsFullCapDeepScanSucceeds(t *testing.T) {
	r := &fakeReader{}
	// 900 candidates, each rooted on a shared 12-deep ACYCLIC folder chain that
	// ends in a grant for alice. Each candidate is its own object whose parent is
	// the top of the shared chain, so every candidate must walk the full depth.
	const cands, depth = 900, 12
	for d := 0; d < depth; d++ {
		r.add("res", fmt.Sprintf("chain%d", d), "parent", set("res", fmt.Sprintf("chain%d", d+1), "viewer"))
	}
	r.add("res", fmt.Sprintf("chain%d", depth), "viewer", user("alice"))
	for c := 0; c < cands; c++ {
		r.add("res", fmt.Sprintf("cand%d", c), "parent", set("res", "chain0", "viewer"))
	}
	cr := &countingReader{fakeReader: r}
	e := NewEngine(StaticResolver(inheritModel()), cr).WithMaxReads(5000) // DefaultMaxCheckReads

	got, err := e.ListObjects(context.Background(), "p", "", "res", "viewer", "alice", 1000) // DefaultMaxListObjects
	if err != nil {
		t.Fatalf("legit full-cap deep scan must succeed, got %v (reads=%d)", err, cr.n)
	}
	// every candidate inherits viewer (plus the chain nodes themselves, which
	// also resolve viewer up the chain): the full list comes back, no truncation.
	if len(got) < cands {
		t.Fatalf("want at least all %d candidates to inherit viewer, got %d", cands, len(got))
	}
}

// TestBudget_CheckSetUsesConfiguredListObjectsCap pins the scaling contract:
// CheckSet sizes its fan-out budget off the engine's configured ListObjects cap
// (WithMaxListObjects), NOT a hardcoded constant. A long member chain whose read
// cost exceeds the budget at the DEFAULT cap must trip the budget; raising the
// cap lifts the budget and lets the same query through.
func TestBudget_CheckSetUsesConfiguredListObjectsCap(t *testing.T) {
	build := func() *countingReader {
		r := &fakeReader{}
		// doc1#viewer is granted to the CONCRETE user alice, so the query set does
		// NOT match structurally — it goes through member resolution. The query set
		// group:wide#member nests n sibling subgroups (a WIDE, shallow fan-out);
		// resolving its members reads every subgroup, charging ~n reads at shallow
		// depth (so the read budget, not maxDepth, is the binding constraint).
		const n = 80
		r.add("doc", "doc1", "viewer", user("alice"))
		for i := 0; i < n; i++ {
			r.add("group", "wide", "member", set("group", fmt.Sprintf("g%d", i), "member"))
			r.add("group", fmt.Sprintf("g%d", i), "member", user(fmt.Sprintf("u%d", i)))
		}
		// alice is in the last subgroup, so a fully-resolved member set DOES grant.
		r.add("group", "g79", "member", user("alice"))
		return &countingReader{fakeReader: r}
	}
	query := ss("group", "wide", "member")
	ctx := context.Background()

	// maxDepth × headroom × candidates sizes the fan-out budget. Use a tiny base
	// maxReads and a tiny cap so the configured cap is the binding factor —
	// proving the cap (not a constant) sizes the budget.
	const base = 10

	// Tiny configured cap → tiny fan-out budget → the chain trips it.
	low := NewEngine(StaticResolver(Model{"doc": {"viewer": this()}, "group": {"member": this()}}), build()).WithMaxReads(base).WithMaxListObjects(1)
	if _, err := low.CheckSet(ctx, "p", "", "doc", "doc1", "viewer", query, nil); !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("low cap: want ErrEvalBudgetExceeded, got %v", err)
	}

	// Raised cap → larger fan-out budget → the same query completes.
	high := NewEngine(StaticResolver(Model{"doc": {"viewer": this()}, "group": {"member": this()}}), build()).WithMaxReads(base).WithMaxListObjects(1000)
	ok, err := high.CheckSet(ctx, "p", "", "doc", "doc1", "viewer", query, nil)
	if err != nil {
		t.Fatalf("high cap: query should complete, got %v", err)
	}
	if !ok {
		t.Fatal("high cap: alice's chain grants viewer; want match")
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
