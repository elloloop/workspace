package service_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// TestBatchCheckBudgetExhaustionIsolated pins that a per-item read-budget
// exhaustion (ResourceExhausted) is ITEM-SPECIFIC: the batch still RETURNS, the
// pathological item's slot carries the error, and its well-formed siblings
// succeed. It is NOT a systemic outage and must not abort the whole batch.
func TestBatchCheckBudgetExhaustionIsolated(t *testing.T) {
	store := memory.New()
	// A self-referential resource parent cycle on "loop": viewer on loop walks
	// parent→viewer forever. The cycle poisons the memo so reads grow without
	// bound; a low per-Check budget turns that into ErrEvalBudgetExceeded
	// (mapped to ErrResourceExhausted by the service).
	const chain = 60
	for i := 1; i <= chain; i++ {
		next := i + 1
		if i == chain {
			next = 1 // close the loop
		}
		obj := fmt.Sprintf("loop%d", i)
		parent := fmt.Sprintf("loop%d", next)
		if err := store.WriteTuples(context.Background(), "default", "", []authz.Tuple{{
			Namespace: "resource", ObjectID: obj, Relation: "parent",
			Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "resource", ObjectID: parent, Relation: "viewer"}},
		}}, nil); err != nil {
			t.Fatalf("seed cycle: %v", err)
		}
	}
	// A clean grant for a sibling item that must succeed despite the bad item.
	if err := store.WriteTuples(context.Background(), "default", "", []authz.Tuple{{
		Namespace: "resource", ObjectID: "ok", Relation: "viewer",
		Subject: authz.Subject{UserID: "alice"},
	}}, nil); err != nil {
		t.Fatalf("seed grant: %v", err)
	}

	svc := service.New(store, nil, nil, service.WithMaxCheckReads(10))
	p := service.Principal{ProjectID: "default"}

	results, err := svc.BatchCheck(context.Background(), p, []service.BatchCheckItem{
		{Namespace: "resource", ObjectID: "loop1", Relation: "viewer", SubjectUserID: "nobody"},
		{Namespace: "resource", ObjectID: "ok", Relation: "viewer", SubjectUserID: "alice"},
	})
	if err != nil {
		t.Fatalf("per-item budget exhaustion must not abort the batch: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	if results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "budget") {
		t.Fatalf("bad item slot must carry the budget error, got %+v", results[0])
	}
	if results[0].Allowed {
		t.Fatal("exhausted item must not be allowed")
	}
	if results[1].Err != nil || !results[1].Allowed {
		t.Fatalf("sibling item must succeed, got %+v", results[1])
	}
}
