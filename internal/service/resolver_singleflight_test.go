package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// countingRepo is a real memory repo that counts GetProject calls (and can
// delay them to widen the single-flight window).
type countingRepo struct {
	*memory.Store
	gets  atomic.Int64
	delay time.Duration
}

func (c *countingRepo) GetProject(ctx context.Context, id string) (*service.Project, error) {
	c.gets.Add(1)
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.Store.GetProject(ctx, id)
}

// TestCheckResolvesProjectOnce: a single Check resolves the project at most
// once (the suspended-check and the model load share one cache entry).
func TestCheckResolvesProjectOnce(t *testing.T) {
	repo := &countingRepo{Store: memory.New()}
	svc := service.New(repo, nil, nil)
	if _, err := svc.Check(context.Background(), service.Principal{ProjectID: "default"},
		"workspace", "w1", "owner", "u1", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n := repo.gets.Load(); n > 1 {
		t.Fatalf("Check triggered %d GetProject calls, want at most 1", n)
	}
}

// TestResolverSingleFlight: many concurrent cold-cache resolves for one project
// collapse to a single store load.
func TestResolverSingleFlight(t *testing.T) {
	repo := &countingRepo{Store: memory.New(), delay: 25 * time.Millisecond}
	svc := service.New(repo, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Check(context.Background(), service.Principal{ProjectID: "default"},
				"workspace", "w1", "owner", "u1", nil)
		}()
	}
	wg.Wait()
	if n := repo.gets.Load(); n != 1 {
		t.Fatalf("single-flight: %d GetProject calls for 50 concurrent cold resolves, want 1", n)
	}
}

// errRepo fails every GetProject with a non-NotFound error.
type errRepo struct{ *memory.Store }

func (errRepo) GetProject(context.Context, string) (*service.Project, error) {
	return nil, errors.New("db down")
}

// TestResolverErrorCarriesProjectID: a resolver/store failure propagates (not
// swallowed) and carries the projectID for diagnosis.
func TestResolverErrorCarriesProjectID(t *testing.T) {
	svc := service.New(errRepo{memory.New()}, nil, nil)
	_, err := svc.Check(context.Background(), service.Principal{ProjectID: "proj-x"},
		"workspace", "w1", "owner", "u1", nil)
	if err == nil {
		t.Fatal("expected the resolver error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "proj-x") {
		t.Fatalf("error should carry the projectID for diagnosis, got: %v", err)
	}
}
