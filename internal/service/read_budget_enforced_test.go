package service_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// wideModel resolves viewer through a tuple-to-userset over `parent` into the
// separate `leafns` namespace, so checking viewer on an object reads its parent
// tupleset once plus the leaf relation on every referenced leaf — a read-count
// knob bounded by width (not the recursion depth cap).
func wideModel(t *testing.T) authz.Model {
	t.Helper()
	m, err := authz.ParseModel([]byte(`{
		"res":   {"parent": {"this": true}, "viewer": {"tupleToUserset": {"tupleset": "parent", "computed": "leaf"}}},
		"leafns":{"leaf": {"this": true}}
	}`))
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	return m
}

// seedWide wires res:root with n leaf pointers into leafns. No leaf grants the
// queried user, so a Check for that user reads EVERY leaf (~n+1 reads) before
// returning false — a deterministic read count (no order-dependent
// short-circuit), the knob the budget bounds.
func seedWide(t *testing.T, store *memory.Store, projectID string, n int) {
	t.Helper()
	var ins []authz.Tuple
	for i := 0; i < n; i++ {
		ins = append(ins, authz.Tuple{
			Namespace: "res", ObjectID: "root", Relation: "parent",
			Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "leafns", ObjectID: fmt.Sprintf("leaf%d", i), Relation: "leaf"}},
		})
		// Each leaf grants only bob, never the queried alice, so alice's Check must
		// scan all leaves.
		ins = append(ins, authz.Tuple{
			Namespace: "leafns", ObjectID: fmt.Sprintf("leaf%d", i), Relation: "leaf",
			Subject: authz.Subject{UserID: "bob"},
		})
	}
	if err := store.WriteTuples(context.Background(), projectID, "", ins, nil); err != nil {
		t.Fatalf("seed %s: %v", projectID, err)
	}
}

// TestCheckUsesPerProjectBudget: with a STINGY global budget, a project carrying
// a high per-project override answers a read-heavy Check that a no-override
// project (on the global default) trips on — proving the resolved override
// threads from project config → resolver → engine, and isolating per project.
func TestCheckUsesPerProjectBudget(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	model := wideModel(t)

	// Stingy global default (100): far below the ~300 reads the graph needs.
	svc := service.New(store, nil, nil, service.WithMaxCheckReads(100))

	// "rich" carries a high override; "plain" stays on the global default.
	if _, err := svc.CreateProject(ctx, "rich", "Rich", model, "", 5000); err != nil {
		t.Fatalf("CreateProject rich: %v", err)
	}
	if _, err := svc.CreateProject(ctx, "plain", "Plain", model, "", 0); err != nil {
		t.Fatalf("CreateProject plain: %v", err)
	}
	seedWide(t, store, "rich", 300)
	seedWide(t, store, "plain", 300)

	// The override project answers the read-heavy Check without tripping the
	// budget (alice is not a member, so the result is a clean deny — the point is
	// that it COMPLETES rather than failing closed with ResourceExhausted).
	if _, err := svc.Check(ctx, service.Principal{ProjectID: "rich"}, "res", "root", "viewer", "alice", nil); err != nil {
		t.Fatalf("rich (override 5000) Check must complete, got %v", err)
	}

	// The no-override project trips the stingy global budget → ResourceExhausted.
	_, err := svc.Check(ctx, service.Principal{ProjectID: "plain"}, "res", "root", "viewer", "alice", nil)
	if !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("plain (global default) Check: want ErrResourceExhausted, got %v", err)
	}
}

// TestCheckLowOverrideTripsBelowGlobal: a LOW per-project override trips a Check
// that the generous GLOBAL default would allow — the override tightens, not just
// loosens, and is isolated to its project.
func TestCheckLowOverrideTripsBelowGlobal(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	model := wideModel(t)

	// Generous global default (5000); a tight per-project override (100) bites.
	svc := service.New(store, nil, nil, service.WithMaxCheckReads(5000))

	if _, err := svc.CreateProject(ctx, "tight", "Tight", model, "", 100); err != nil {
		t.Fatalf("CreateProject tight: %v", err)
	}
	if _, err := svc.CreateProject(ctx, "open", "Open", model, "", 0); err != nil {
		t.Fatalf("CreateProject open: %v", err)
	}
	seedWide(t, store, "tight", 300)
	seedWide(t, store, "open", 300)

	_, err := svc.Check(ctx, service.Principal{ProjectID: "tight"}, "res", "root", "viewer", "alice", nil)
	if !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("tight (override 100) Check: want ErrResourceExhausted, got %v", err)
	}
	// The sibling project on the generous global default answers the same graph
	// without tripping — the override is isolated to its own project.
	if _, err := svc.Check(ctx, service.Principal{ProjectID: "open"}, "res", "root", "viewer", "alice", nil); err != nil {
		t.Fatalf("open (global default 5000) Check must complete, got %v", err)
	}
}
