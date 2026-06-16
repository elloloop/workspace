package service

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/elloloop/workspace/pkg/authz"
)

// fakeProjectRepo satisfies Repository via an embedded (nil) interface and only
// implements the project reads the resolver touches; any other call would panic,
// which is the point — the resolver must read nothing else.
type fakeProjectRepo struct {
	Repository
	projects map[string]*Project
	getCalls int
}

func (f *fakeProjectRepo) GetProject(_ context.Context, id string) (*Project, error) {
	f.getCalls++
	if p, ok := f.projects[id]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}

func newTestResolver(repo Repository) *modelResolver {
	r := newModelResolver(repo)
	r.ttl = time.Minute
	r.max = 8
	return r
}

func TestResolverUnknownProjectsShareDefaultModel(t *testing.T) {
	r := newTestResolver(&fakeProjectRepo{projects: map[string]*Project{}})
	ctx := context.Background()

	e, err := r.resolve(ctx, "ghost")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if e.model != nil {
		t.Fatalf("unknown project should cache a nil model (shared default), got a per-key map")
	}
	// modelOrDefault hands back the single shared instance, not a fresh copy.
	if got := e.modelOrDefault(); len(got) != len(sharedDefaultModel) {
		t.Fatalf("unknown project model = %v, want the shared default", got)
	}
}

func TestResolverCacheIsBounded(t *testing.T) {
	r := newTestResolver(&fakeProjectRepo{projects: map[string]*Project{}})
	ctx := context.Background()
	for i := 0; i < 200; i++ {
		if _, err := r.ModelFor(ctx, "p"+strconv.Itoa(i)); err != nil {
			t.Fatalf("ModelFor: %v", err)
		}
	}
	r.mu.Lock()
	n := len(r.cache)
	r.mu.Unlock()
	if n > r.max {
		t.Fatalf("cache grew to %d entries, want <= cap %d (memory-amplification guard)", n, r.max)
	}
}

func TestResolverTTLExpiry(t *testing.T) {
	repo := &fakeProjectRepo{projects: map[string]*Project{}}
	r := newTestResolver(repo)
	now := time.Unix(0, 0)
	r.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := r.ModelFor(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ModelFor(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if repo.getCalls != 1 {
		t.Fatalf("within TTL GetProject calls = %d, want 1 (cached)", repo.getCalls)
	}
	now = now.Add(2 * r.ttl) // expire the entry
	if _, err := r.ModelFor(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if repo.getCalls != 2 {
		t.Fatalf("after TTL GetProject calls = %d, want 2 (re-resolved)", repo.getCalls)
	}
}

func TestResolverReportsSuspended(t *testing.T) {
	repo := &fakeProjectRepo{projects: map[string]*Project{
		"live": {ID: "live", Status: ProjectActive},
		"dead": {ID: "dead", Status: ProjectSuspended},
	}}
	r := newTestResolver(repo)
	ctx := context.Background()

	if susp, _ := r.suspended(ctx, "live"); susp {
		t.Fatal("active project reported suspended")
	}
	if susp, _ := r.suspended(ctx, "dead"); !susp {
		t.Fatal("suspended project not reported suspended")
	}
	if susp, _ := r.suspended(ctx, "ghost"); susp {
		t.Fatal("unknown project reported suspended")
	}
}

func TestResolverConfiguredModelOverlaysDefaults(t *testing.T) {
	custom := authz.Model{"course": {"viewer": {}}}
	repo := &fakeProjectRepo{projects: map[string]*Project{
		"pro": {ID: "pro", Status: ProjectActive, Model: custom},
	}}
	r := newTestResolver(repo)

	m, err := r.ModelFor(context.Background(), "pro")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["course"]; !ok {
		t.Fatal("custom namespace missing")
	}
	if _, ok := m["workspace"]; !ok {
		t.Fatal("built-in workspace namespace lost under custom model (overlay broken)")
	}
}
