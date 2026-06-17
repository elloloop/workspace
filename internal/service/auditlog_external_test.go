package service_test

import (
	"context"
	"sync"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

type capturingAudit struct {
	mu     sync.Mutex
	tuples []service.TupleChangeRecord
	admins []service.AdminAuditRecord
}

func (c *capturingAudit) LogTupleChange(_ context.Context, r service.TupleChangeRecord) {
	c.mu.Lock()
	c.tuples = append(c.tuples, r)
	c.mu.Unlock()
}

func (c *capturingAudit) LogAdminMutation(_ context.Context, r service.AdminAuditRecord) {
	c.mu.Lock()
	c.admins = append(c.admins, r)
	c.mu.Unlock()
}

func (c *capturingAudit) tupleRecs() []service.TupleChangeRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]service.TupleChangeRecord(nil), c.tuples...)
}

func (c *capturingAudit) adminRecs() []service.AdminAuditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]service.AdminAuditRecord(nil), c.admins...)
}

func TestAuditTupleChanges(t *testing.T) {
	a := &capturingAudit{}
	svc := service.New(memory.New(), nil, nil, service.WithAuditLogger(a))
	p := service.Principal{ProjectID: "p", TenantID: "t1"}

	if _, err := svc.WriteTuples(context.Background(), p, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "viewer", Subject: authz.Subject{UserID: "bob"}}},
		{Delete: true, Tuple: authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "editor", Subject: authz.Subject{UserID: "carol"}}},
	}); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}
	recs := a.tupleRecs()
	if len(recs) != 2 {
		t.Fatalf("got %d tuple records, want 2: %+v", len(recs), recs)
	}
	var ins, del *service.TupleChangeRecord
	for i := range recs {
		switch recs[i].Op {
		case service.TupleOpInsert:
			ins = &recs[i]
		case service.TupleOpDelete:
			del = &recs[i]
		}
	}
	if ins == nil || ins.SubjectUserID != "bob" || ins.Relation != "viewer" || ins.ProjectID != "p" || ins.TenantID != "t1" {
		t.Fatalf("insert record wrong: %+v", ins)
	}
	if del == nil || del.SubjectUserID != "carol" || del.Relation != "editor" {
		t.Fatalf("delete record wrong: %+v", del)
	}
}

func TestAuditAdminMutations(t *testing.T) {
	a := &capturingAudit{}
	svc := service.New(memory.New(), nil, nil, service.WithAuditLogger(a))
	ctx := context.Background()
	model, err := authz.ParseModel([]byte(`{"course":{"viewer":{"this":true}}}`))
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	if _, err := svc.CreateProject(ctx, "prj", "Kids", model); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// status-only update: StatusChanged true, ModelChanged false.
	if _, err := svc.UpdateProject(ctx, "prj", "", service.ProjectSuspended, nil); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	recs := a.adminRecs()
	if len(recs) != 2 {
		t.Fatalf("got %d admin records, want 2: %+v", len(recs), recs)
	}
	if recs[0].Action != service.AdminActionCreateProject || recs[0].ProjectID != "prj" || !recs[0].ModelChanged {
		t.Fatalf("create record wrong: %+v", recs[0])
	}
	upd := recs[1]
	if upd.Action != service.AdminActionUpdateProject || !upd.StatusChanged || upd.NewStatus != service.ProjectSuspended || upd.ModelChanged {
		t.Fatalf("update record wrong: %+v", upd)
	}
}

func TestAuditDisabledNoEmit(t *testing.T) {
	// A Service without an audit logger must work and never panic (nil-guarded).
	svc := service.New(memory.New(), nil, nil)
	p := service.Principal{ProjectID: "p"}
	if _, err := svc.WriteTuples(context.Background(), p, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "viewer", Subject: authz.Subject{UserID: "bob"}}},
	}); err != nil {
		t.Fatalf("WriteTuples (no audit): %v", err)
	}
}
