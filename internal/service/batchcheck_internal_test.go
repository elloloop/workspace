package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// boomRepo is a real memory repo whose tuple reads always fail, simulating a
// storage/engine outage on the Check hot path.
type boomRepo struct {
	*memory.Store
}

func (boomRepo) ListSubjects(context.Context, string, string, string, string, string) ([]authz.Subject, error) {
	return nil, errors.New("storage boom")
}

// TestBatchCheckInternalErrorAborts pins the error policy: a storage/engine
// failure aborts the whole batch (surfaced as an error) rather than hiding in a
// per-item result string, while a per-item validation error stays isolated.
func TestBatchCheckInternalErrorAborts(t *testing.T) {
	svc := service.New(boomRepo{memory.New()}, nil, nil)
	p := service.Principal{ProjectID: "default"}

	// A well-formed item whose Check hits the failing store must abort the batch.
	results, err := svc.BatchCheck(context.Background(), p, []service.BatchCheckItem{
		{Namespace: "workspace", ObjectID: "w1", Relation: "owner", SubjectUserID: "u1"},
	})
	if err == nil {
		t.Fatal("internal storage error must abort the batch, not hide in a result")
	}
	if results != nil {
		t.Fatalf("expected nil results on abort, got %v", results)
	}

	// A malformed item (empty relation) is a validation error, isolated to its
	// own slot — it does not reach the store, so the batch still returns.
	results, err = svc.BatchCheck(context.Background(), p, []service.BatchCheckItem{
		{Namespace: "workspace", ObjectID: "w1", Relation: "", SubjectUserID: "u1"},
	})
	if err != nil {
		t.Fatalf("validation error must not abort the batch: %v", err)
	}
	if len(results) != 1 || results[0].Err == nil || results[0].Allowed {
		t.Fatalf("validation error must be isolated in its slot: %+v", results)
	}
}
