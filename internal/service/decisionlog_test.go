package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

type capturingLogger struct {
	mu   sync.Mutex
	recs []service.DecisionRecord
}

func (c *capturingLogger) Log(_ context.Context, r service.DecisionRecord) {
	c.mu.Lock()
	c.recs = append(c.recs, r)
	c.mu.Unlock()
}

func (c *capturingLogger) records() []service.DecisionRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]service.DecisionRecord(nil), c.recs...)
}

func seedOwner(t *testing.T, repo service.Repository) {
	t.Helper()
	err := repo.WriteTuples(context.Background(), "p", "", []authz.Tuple{{
		Namespace: "workspace", ObjectID: "w1", Relation: "owner",
		Subject: authz.Subject{UserID: "alice"},
	}}, nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestCheckEmitsDecisionRecord(t *testing.T) {
	repo := memory.New()
	cap := &capturingLogger{}
	svc := service.New(repo, nil, nil, service.WithDecisionLogger(cap))
	seedOwner(t, repo)
	p := service.Principal{ProjectID: "p"}

	// An allow.
	allowed, err := svc.Check(context.Background(), p, "workspace", "w1", "owner", "alice", nil)
	if err != nil || !allowed {
		t.Fatalf("Check alice = %v, %v; want allowed", allowed, err)
	}
	// A deny.
	if allowed, _ := svc.Check(context.Background(), p, "workspace", "w1", "owner", "bob", nil); allowed {
		t.Fatal("Check bob should be denied")
	}

	recs := cap.records()
	if len(recs) != 2 {
		t.Fatalf("got %d decision records, want 2", len(recs))
	}
	if !recs[0].Allowed || recs[0].SubjectUserID != "alice" || recs[0].Namespace != "workspace" ||
		recs[0].ObjectID != "w1" || recs[0].Relation != "owner" || recs[0].ProjectID != "p" {
		t.Fatalf("allow record = %+v", recs[0])
	}
	if recs[1].Allowed || recs[1].SubjectUserID != "bob" {
		t.Fatalf("deny record = %+v", recs[1])
	}
}

func TestCheckWithoutLoggerWorks(t *testing.T) {
	repo := memory.New()
	svc := service.New(repo, nil, nil) // no decision logger
	seedOwner(t, repo)
	allowed, err := svc.Check(context.Background(), service.Principal{ProjectID: "p"}, "workspace", "w1", "owner", "alice", nil)
	if err != nil || !allowed {
		t.Fatalf("Check with nil logger = %v, %v; want allowed", allowed, err)
	}
}
