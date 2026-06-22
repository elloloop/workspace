// Package auditlog provides a concrete, async service.AuditLogger that drains
// relation-tuple changes and admin mutations to a structured zap logger off the
// hot path. It is wired in by the server when GATEWAY_AUDIT_LOG is enabled; the
// service package itself stays transport/logging-agnostic. It mirrors the async
// non-blocking design of internal/decisionlog.
package auditlog

import (
	"context"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/elloloop/workspace/internal/service"
)

// DefaultBufferSize bounds how many pending audit events are buffered before new
// ones are dropped (rather than blocking the audited write).
const DefaultBufferSize = 4096

// event is one buffered audit record: exactly one of tuple/admin is set.
type event struct {
	tuple *service.TupleChangeRecord
	admin *service.AdminAuditRecord
}

// ZapLogger is an async, non-blocking service.AuditLogger. Log* enqueue a record
// and return immediately; a background goroutine drains the buffer to the zap
// logger. When the buffer is full, records are DROPPED and counted — the audited
// operation is never blocked or failed by auditing.
type ZapLogger struct {
	logger    *zap.Logger
	ch        chan event
	quit      chan struct{}
	done      chan struct{}
	dropped   atomic.Int64
	closeOnce sync.Once
}

var _ service.AuditLogger = (*ZapLogger)(nil)

// NewZap starts a ZapLogger draining to logger. A non-positive bufSize uses
// DefaultBufferSize. Call Close to stop the goroutine and flush buffered events.
func NewZap(logger *zap.Logger, bufSize int) *ZapLogger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	z := &ZapLogger{
		logger: logger,
		ch:     make(chan event, bufSize),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go z.run()
	return z
}

// LogTupleChange enqueues a relation-tuple grant/revocation without blocking.
func (z *ZapLogger) LogTupleChange(_ context.Context, rec service.TupleChangeRecord) {
	z.enqueue(event{tuple: &rec})
}

// LogAdminMutation enqueues an admin-mutation record without blocking.
func (z *ZapLogger) LogAdminMutation(_ context.Context, rec service.AdminAuditRecord) {
	z.enqueue(event{admin: &rec})
}

// enqueue buffers an event; drops+counts when full or shutting down. The data
// channel is never closed, so enqueue can never panic on a concurrent Close.
func (z *ZapLogger) enqueue(e event) {
	select {
	case z.ch <- e:
	case <-z.quit:
	default:
		z.dropped.Add(1)
	}
}

func (z *ZapLogger) run() {
	defer close(z.done)
	for {
		select {
		case e := <-z.ch:
			z.emit(e)
		case <-z.quit:
			for {
				select {
				case e := <-z.ch:
					z.emit(e)
				default:
					return
				}
			}
		}
	}
}

func (z *ZapLogger) emit(e event) {
	switch {
	case e.tuple != nil:
		r := e.tuple
		fields := []zap.Field{
			zap.String("op", string(r.Op)),
			zap.String("project", r.ProjectID),
			zap.String("tenant", r.TenantID),
			zap.String("namespace", r.Namespace),
			zap.String("object", r.ObjectID),
			zap.String("relation", r.Relation),
			zap.Time("at", r.At),
		}
		switch {
		case r.Wildcard:
			fields = append(fields, zap.String("subject", "*"))
		case r.SubjectSet != nil:
			fields = append(fields, zap.String("subject",
				r.SubjectSet.Namespace+":"+r.SubjectSet.ObjectID+"#"+r.SubjectSet.Relation))
		default:
			fields = append(fields, zap.String("subject", r.SubjectUserID))
		}
		if r.Caller != "" {
			fields = append(fields, zap.String("caller", r.Caller))
		}
		z.logger.Info("authz_tuple_change", fields...)
	case e.admin != nil:
		r := e.admin
		z.logger.Info("authz_admin_mutation",
			zap.String("action", string(r.Action)),
			zap.String("project", r.ProjectID),
			zap.String("new_status", string(r.NewStatus)),
			zap.Bool("status_changed", r.StatusChanged),
			zap.Bool("model_changed", r.ModelChanged),
			zap.Bool("region_changed", r.RegionChanged),
			zap.Bool("budget_changed", r.BudgetChanged),
			zap.Time("at", r.At),
		)
	}
}

// Dropped returns the number of audit events dropped because the buffer was full.
func (z *ZapLogger) Dropped() int64 { return z.dropped.Load() }

// Close stops the background goroutine after draining buffered events. It is
// idempotent and safe to call from shutdown.
func (z *ZapLogger) Close() {
	z.closeOnce.Do(func() {
		close(z.quit)
		<-z.done
		if n := z.dropped.Load(); n > 0 {
			z.logger.Warn("authz_audit_log_dropped", zap.Int64("count", n))
		}
	})
}
