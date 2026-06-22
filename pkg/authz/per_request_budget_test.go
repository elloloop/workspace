package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// wideViewerModel resolves viewer through a tuple-to-userset over `parent`:
// viewer = leaf-relation on every object referenced under `parent`. Checking
// viewer on an object reads its `parent` tupleset once, then the `leaf` relation
// on each referenced leaf (depth 1) — so a root with N parent pointers costs
// ~N+1 store reads. This is the read-count knob (width, not depth, so the
// recursion cap never interferes).
func wideViewerModel() Model {
	return Model{
		"res": {
			"viewer": tupleToUserset("parent", "leaf"),
		},
		"leafns": {
			"leaf": this(),
		},
	}
}

// buildWide wires a res:root with n distinct leaf pointers (into the separate
// leafns namespace, so the leaves are NOT res candidate objects), granting the
// user only on the LAST leaf so a satisfied Check still reads (nearly) every
// leaf.
func buildWide(n int, userID string) *fakeReader {
	r := &fakeReader{}
	for i := 0; i < n; i++ {
		r.add("res", "root", "parent", set("leafns", fmt.Sprintf("leaf%d", i), "leaf"))
	}
	r.add("leafns", fmt.Sprintf("leaf%d", n-1), "leaf", user(userID))
	return r
}

// TestPerRequestBudget_OverrideTripsBelowGlobal: a LOW per-project override
// trips a Check on a graph the generous GLOBAL default (5000) allows — proving
// the per-request override replaces the engine default budget.
func TestPerRequestBudget_OverrideTripsBelowGlobal(t *testing.T) {
	cr := &countingReader{fakeReader: buildWide(1000, "alice")}
	e := NewEngine(StaticResolver(wideViewerModel()), cr).WithMaxReads(5000)

	ok, err := e.CheckWithModel(context.Background(), wideViewerModel(), "p", "", "res", "root", "viewer", "alice", nil, 0)
	if err != nil || !ok {
		t.Fatalf("global-default Check: ok=%v err=%v (reads=%d)", ok, err, cr.n)
	}
	if cr.n <= 100 {
		t.Fatalf("fixture must read more than the override floor to prove the override bites, reads=%d", cr.n)
	}
	_, err = e.CheckWithModel(context.Background(), wideViewerModel(), "p", "", "res", "root", "viewer", "alice", nil, 100)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("low override Check: want ErrEvalBudgetExceeded, got %v", err)
	}
}

// TestPerRequestBudget_OverrideAllowsAboveGlobal: a HIGH per-project override
// allows a Check on a graph the engine's LOW global default trips — the
// read-heavy-tenant case the override exists for.
func TestPerRequestBudget_OverrideAllowsAboveGlobal(t *testing.T) {
	cr := &countingReader{fakeReader: buildWide(1000, "alice")}
	e := NewEngine(StaticResolver(wideViewerModel()), cr).WithMaxReads(100)

	_, err := e.CheckWithModel(context.Background(), wideViewerModel(), "p", "", "res", "root", "viewer", "alice", nil, 0)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("stingy global Check: want ErrEvalBudgetExceeded, got %v", err)
	}
	ok, err := e.CheckWithModel(context.Background(), wideViewerModel(), "p", "", "res", "root", "viewer", "alice", nil, 5000)
	if err != nil || !ok {
		t.Fatalf("high override Check: ok=%v err=%v", ok, err)
	}
}

// TestPerRequestBudget_ListObjectsThreadsOverride: the per-request override is
// the BASE the ListObjects fan-out budget scales off (fanOutBudget never drops
// below its base). With a stingy global default and a bounded candidate cap the
// candidate-scaled budget is tiny, so checking the read-heavy `root` (~1000
// reads) trips — UNLESS the per-request override raises the base. This proves
// the override threads all the way into ListObjects.
func TestPerRequestBudget_ListObjectsThreadsOverride(t *testing.T) {
	// Only res:root is a candidate object in `res` (the 1000 leaves live in the
	// separate leafns namespace), so the candidate-scaled fan-out budget is tiny
	// while checking root reads ~1000 tuples.
	cr := &countingReader{fakeReader: buildWide(1000, "alice")}
	e := NewEngine(StaticResolver(wideViewerModel()), cr).WithMaxReads(100)

	// candidate cap 1 → candidate-scaled budget 1×32×2=64; root reads ~1001.
	// Global base (100) → fan-out budget max(100,64)=100 → trips on root.
	_, err := e.ListObjectsWithModel(context.Background(), wideViewerModel(), "p", "", "res", "viewer", "alice", 1, 0)
	if !errors.Is(err, ErrEvalBudgetExceeded) {
		t.Fatalf("stingy ListObjects must trip on read-heavy root, got %v (reads=%d)", err, cr.n)
	}
	// Same query, high per-request override (5000) → fan-out budget max(5000,128)
	// = 5000 → the scan completes and finds root.
	ids, err := e.ListObjectsWithModel(context.Background(), wideViewerModel(), "p", "", "res", "viewer", "alice", 1, 5000)
	if err != nil {
		t.Fatalf("high override ListObjects: %v", err)
	}
	found := false
	for _, id := range ids {
		if id == "root" {
			found = true
		}
	}
	if !found {
		t.Fatalf("high override ListObjects must include root, got %v", ids)
	}
}

// TestPerRequestBudget_EffectiveMaxReads pins the override-vs-default resolution.
func TestPerRequestBudget_EffectiveMaxReads(t *testing.T) {
	e := NewEngine(StaticResolver(DefaultModel()), &fakeReader{}).WithMaxReads(5000)
	if got := e.effectiveMaxReads(0); got != 5000 {
		t.Fatalf("override 0 => global default, got %d", got)
	}
	if got := e.effectiveMaxReads(-1); got != 5000 {
		t.Fatalf("override <0 => global default, got %d", got)
	}
	if got := e.effectiveMaxReads(250); got != 250 {
		t.Fatalf("positive override wins, got %d", got)
	}
}
