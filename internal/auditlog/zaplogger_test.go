package auditlog

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/workspace/internal/service"
)

func TestZapLoggerEmitsBothKindsAndCloses(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	z := NewZap(zap.New(core), 0)

	z.LogTupleChange(context.Background(), service.TupleChangeRecord{
		Op: service.TupleOpInsert, ProjectID: "p", TenantID: "t1",
		Namespace: "doc", ObjectID: "d1", Relation: "viewer", SubjectUserID: "bob", At: time.Unix(1, 0),
	})
	z.LogAdminMutation(context.Background(), service.AdminAuditRecord{
		Action: service.AdminActionUpdateProject, ProjectID: "prj",
		NewStatus: service.ProjectSuspended, StatusChanged: true, ModelChanged: false, At: time.Unix(2, 0),
	})
	z.Close() // drains before returning

	entries := logs.All()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	byMsg := map[string]map[string]any{}
	for _, e := range entries {
		byMsg[e.Message] = e.ContextMap()
	}
	tc := byMsg["authz_tuple_change"]
	if tc == nil || tc["op"] != "insert" || tc["subject"] != "bob" || tc["namespace"] != "doc" || tc["tenant"] != "t1" {
		t.Fatalf("tuple_change fields = %v", tc)
	}
	am := byMsg["authz_admin_mutation"]
	if am == nil || am["action"] != "update_project" || am["status_changed"] != true || am["new_status"] != "suspended" {
		t.Fatalf("admin_mutation fields = %v", am)
	}
	// The admin secret must never appear anywhere in the audit output.
	for _, e := range entries {
		for k, v := range e.ContextMap() {
			if k == "secret" || v == "secret" {
				t.Fatalf("secret leaked into audit record: %v", e.ContextMap())
			}
		}
	}
}

type blockingSyncer struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingSyncer) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}
func (b *blockingSyncer) Sync() error { return nil }

func TestZapLoggerDropsWhenFull(t *testing.T) {
	b := &blockingSyncer{entered: make(chan struct{}), release: make(chan struct{})}
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(b), zapcore.InfoLevel))
	z := NewZap(logger, 1) // buffer of 1

	rec := func(u string) service.TupleChangeRecord {
		return service.TupleChangeRecord{Op: service.TupleOpInsert, ProjectID: "p", Namespace: "n", ObjectID: "o", Relation: "r", SubjectUserID: u, At: time.Unix(1, 0)}
	}
	z.LogTupleChange(context.Background(), rec("a")) // drained, goroutine blocks in Write
	<-b.entered                                      // goroutine pinned; buffer empty
	z.LogTupleChange(context.Background(), rec("b")) // fills size-1 buffer
	z.LogTupleChange(context.Background(), rec("c")) // full -> dropped

	if got := z.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	close(b.release)
	z.Close() // must not deadlock; drains and stops
}

func TestZapLoggerCloseIdempotent(t *testing.T) {
	z := NewZap(zap.NewNop(), 0)
	z.Close()
	z.Close() // safe no-op
	// Log after Close must not panic.
	z.LogAdminMutation(context.Background(), service.AdminAuditRecord{ProjectID: "p"})
	z.LogTupleChange(context.Background(), service.TupleChangeRecord{ProjectID: "p"})
}
