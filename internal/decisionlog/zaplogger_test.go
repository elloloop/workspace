package decisionlog

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

func TestZapLoggerEmitsAndCloses(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	z := NewZap(zap.New(core), 0)

	z.Log(context.Background(), service.DecisionRecord{
		ProjectID: "p", Namespace: "workspace", ObjectID: "w1", Relation: "owner",
		SubjectUserID: "alice", Allowed: true, DecidedAt: time.Unix(1, 0),
	})
	z.Close() // drains buffered records before returning

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Message != "authz_decision" {
		t.Fatalf("message = %q", e.Message)
	}
	fields := e.ContextMap()
	if fields["allowed"] != true {
		t.Fatalf("allowed field = %v", fields["allowed"])
	}
	if fields["subject_user"] != "alice" || fields["object"] != "w1" {
		t.Fatalf("fields = %v", fields)
	}
}

// blockingSyncer signals when its first Write begins (entered) and blocks until
// release is closed, letting a test pin the drain goroutine in place.
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

	rec := func(u string) service.DecisionRecord {
		return service.DecisionRecord{ProjectID: "p", Namespace: "n", ObjectID: "o", Relation: "r", SubjectUserID: u, DecidedAt: time.Unix(1, 0)}
	}
	z.Log(context.Background(), rec("a")) // drained by goroutine, which blocks in Write
	<-b.entered                           // goroutine now pinned writing "a"; buffer empty
	z.Log(context.Background(), rec("b")) // fills the size-1 buffer
	z.Log(context.Background(), rec("c")) // buffer full -> dropped

	if got := z.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	close(b.release) // unblock the goroutine
	z.Close()        // must not deadlock; drains and stops
}

func TestZapLoggerCloseIdempotent(t *testing.T) {
	z := NewZap(zap.NewNop(), 0)
	z.Close()
	z.Close() // second Close must be a safe no-op (no panic, no hang)
	// Log after Close must not panic.
	z.Log(context.Background(), service.DecisionRecord{ProjectID: "p"})
}
