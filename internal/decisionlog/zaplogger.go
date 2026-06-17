// Package decisionlog provides a concrete, async service.DecisionLogger that
// drains authorization decisions to a structured zap logger off the hot path.
// It is wired in by the server when GATEWAY_DECISION_LOG is enabled; the
// service package itself stays transport/logging-agnostic.
package decisionlog

import (
	"context"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/elloloop/workspace/internal/service"
)

// DefaultBufferSize bounds how many pending decisions are buffered before new
// ones are dropped (rather than blocking a Check).
const DefaultBufferSize = 4096

// ZapLogger is an async, non-blocking service.DecisionLogger. Log enqueues a
// record and returns immediately; a background goroutine drains the buffer to
// the zap logger. When the buffer is full, records are DROPPED and counted —
// the authorization path is never blocked or failed by logging.
type ZapLogger struct {
	logger    *zap.Logger
	ch        chan service.DecisionRecord
	quit      chan struct{}
	done      chan struct{}
	dropped   atomic.Int64
	closeOnce sync.Once
}

var _ service.DecisionLogger = (*ZapLogger)(nil)

// NewZap starts a ZapLogger draining to logger. A non-positive bufSize uses
// DefaultBufferSize. Call Close to stop the goroutine and flush buffered
// records.
func NewZap(logger *zap.Logger, bufSize int) *ZapLogger {
	if logger == nil {
		logger = zap.NewNop()
	}
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	z := &ZapLogger{
		logger: logger,
		ch:     make(chan service.DecisionRecord, bufSize),
		quit:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go z.run()
	return z
}

// Log enqueues a decision without blocking. If the buffer is full the record is
// dropped and counted; after Close it is silently dropped. The data channel is
// never closed, so Log can never panic on a concurrent shutdown.
func (z *ZapLogger) Log(_ context.Context, rec service.DecisionRecord) {
	select {
	case z.ch <- rec:
	case <-z.quit:
		// shutting down; drop
	default:
		z.dropped.Add(1)
	}
}

func (z *ZapLogger) run() {
	defer close(z.done)
	for {
		select {
		case rec := <-z.ch:
			z.emit(rec)
		case <-z.quit:
			// drain whatever is buffered, then exit
			for {
				select {
				case rec := <-z.ch:
					z.emit(rec)
				default:
					return
				}
			}
		}
	}
}

func (z *ZapLogger) emit(rec service.DecisionRecord) {
	fields := []zap.Field{
		zap.String("project", rec.ProjectID),
		zap.String("tenant", rec.TenantID),
		zap.String("namespace", rec.Namespace),
		zap.String("object", rec.ObjectID),
		zap.String("relation", rec.Relation),
		zap.Bool("allowed", rec.Allowed),
		zap.Time("decided_at", rec.DecidedAt),
	}
	if rec.SubjectUserID != "" {
		fields = append(fields, zap.String("subject_user", rec.SubjectUserID))
	}
	if rec.SubjectSet != nil {
		fields = append(fields, zap.String("subject_set",
			rec.SubjectSet.Namespace+":"+rec.SubjectSet.ObjectID+"#"+rec.SubjectSet.Relation))
	}
	if rec.Caller != "" {
		fields = append(fields, zap.String("caller", rec.Caller))
	}
	if rec.Err != "" {
		fields = append(fields, zap.String("error", rec.Err))
	}
	z.logger.Info("authz_decision", fields...)
}

// Dropped returns the number of decisions dropped because the buffer was full.
func (z *ZapLogger) Dropped() int64 { return z.dropped.Load() }

// Close stops the background goroutine after draining buffered records. It is
// idempotent and safe to call from shutdown.
func (z *ZapLogger) Close() {
	z.closeOnce.Do(func() {
		close(z.quit)
		<-z.done
		if n := z.dropped.Load(); n > 0 {
			z.logger.Warn("authz_decision_log_dropped", zap.Int64("count", n))
		}
	})
}
