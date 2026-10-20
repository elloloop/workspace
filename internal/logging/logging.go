// Package logging builds the service logger: zap's production JSON on stderr
// and, when OTEL_EXPORTER_OTLP_ENDPOINT is set, the same records exported over
// OTLP/HTTP to a collector. The OpenTelemetry SDK reads the standard OTEL_*
// variables itself (endpoint, headers, OTEL_SERVICE_NAME,
// OTEL_RESOURCE_ATTRIBUTES), so a deploy configures the export without code.
package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// EndpointEnv turns the export on: the collector's base URL, to which the
	// SDK appends /v1/logs. Unset, empty or blank leaves stderr as the only output.
	EndpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"
	// defaultServiceName is service.name when OTEL_SERVICE_NAME does not set one.
	defaultServiceName = "workspace"
	// instrumentationScope names the bridge's logger on exported records.
	instrumentationScope = "github.com/elloloop/workspace"
	// flushTimeout bounds how long Close waits for queued records to reach the collector.
	flushTimeout = 5 * time.Second
	// samplingTick is the window zap's production config samples over
	// (zap.Config.Build hardcodes it; the counts come from NewProductionConfig).
	samplingTick = time.Second
	// errorReportInterval is the most often an export failure is logged.
	errorReportInterval = time.Minute
)

// Logger is the service logger plus the export it may own.
type Logger struct {
	*zap.Logger
	// shutdown flushes and stops the export; nil when the export is off.
	shutdown     func(context.Context) error
	flushTimeout time.Duration
}

// New returns the service logger. With the export off it behaves as
// zap.NewProduction. With it on, the export never blocks a caller: records
// queue in the SDK's bounded batch buffer, which overwrites its oldest records
// when full, and failures (an unreachable collector, an unparseable endpoint,
// a malformed resource attribute) are logged at most once a minute. An export
// the SDK cannot build is reported the same way and left off; it never stops
// the service from starting. A Fatal line is flushed before the process exits; call
// Close before exiting otherwise.
func New(ctx context.Context) (*Logger, error) { return newLogger(ctx, os.Exit) }

func newLogger(ctx context.Context, exit func(int), opts ...zap.Option) (*Logger, error) {
	l := &Logger{flushTimeout: flushTimeout}
	opts = append(opts, zap.WithFatalHook(exitAfter{flush: l.Close, exit: exit}))
	// zap.NewProduction, with its sampler lifted out so it can sit outside the
	// tee below: stderr and the export then keep and drop the same lines.
	cfg := zap.NewProductionConfig()
	sampling := cfg.Sampling
	cfg.Sampling = nil
	unsampled, err := cfg.Build(opts...)
	if err != nil {
		return nil, fmt.Errorf("logging: build the stderr logger: %w", err)
	}
	sample := func(c zapcore.Core) zapcore.Core {
		return zapcore.NewSamplerWithOptions(c, samplingTick, sampling.Initial, sampling.Thereafter)
	}
	local := unsampled.WithOptions(zap.WrapCore(sample))
	l.Logger = local
	if strings.TrimSpace(os.Getenv(EndpointEnv)) == "" {
		return l, nil
	}
	// Installed before the exporter is built, so the SDK's own complaints about
	// its configuration (an unparseable endpoint) are reported the same way.
	otel.SetErrorHandler(newErrorReporter(local, time.Now))
	provider, err := newProvider(ctx)
	if err != nil {
		// The export is optional; the engine must boot without it.
		otel.Handle(fmt.Errorf("export off, logging to stderr only: %w", err))
		return l, nil
	}
	exported := otelzap.NewCore(instrumentationScope, otelzap.WithLoggerProvider(provider))
	l.Logger = unsampled.WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
		return sample(zapcore.NewTee(c, levelled{Core: exported, LevelEnabler: c}))
	}))
	l.shutdown = provider.Shutdown
	return l, nil
}

// Close writes out the local output and flushes the export within its budget.
// It is safe to call more than once.
func (l *Logger) Close() error {
	// Sync on stderr reports EINVAL for a terminal or pipe on some platforms;
	// there is nothing buffered to lose, so its error is not the caller's concern.
	_ = l.Sync()
	if l.shutdown == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.flushTimeout)
	defer cancel()
	if err := l.shutdown(ctx); err != nil {
		return fmt.Errorf("logging: flush the export: %w", err)
	}
	return nil
}

func newProvider(ctx context.Context) (*sdklog.LoggerProvider, error) {
	exp, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("logging: build the OTLP exporter: %w", err)
	}
	// Later options override earlier ones, so OTEL_SERVICE_NAME and
	// OTEL_RESOURCE_ATTRIBUTES win over the default service name.
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", defaultServiceName)),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
	)
	switch {
	case errors.Is(err, resource.ErrPartialResource):
		// A malformed OTEL_RESOURCE_ATTRIBUTES entry: keep the attributes that
		// parsed and say which did not.
		otel.Handle(fmt.Errorf("logging: build the resource: %w", err))
	case err != nil:
		return nil, errors.Join(fmt.Errorf("logging: build the resource: %w", err), exp.Shutdown(ctx))
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	), nil
}

// levelled gives the exported core the local core's level, so the collector
// receives exactly the levels the local output does.
type levelled struct {
	zapcore.Core
	zapcore.LevelEnabler
}

func (l levelled) Enabled(lvl zapcore.Level) bool { return l.LevelEnabler.Enabled(lvl) }

func (l levelled) With(fields []zapcore.Field) zapcore.Core {
	return levelled{Core: l.Core.With(fields), LevelEnabler: l.LevelEnabler}
}

func (l levelled) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !l.Enabled(e.Level) {
		return ce
	}
	return l.Core.Check(e, ce)
}

// exitAfter is the Fatal hook: flush everything, then exit as zap would.
type exitAfter struct {
	flush func() error
	exit  func(int)
}

func (h exitAfter) OnWrite(*zapcore.CheckedEntry, []zapcore.Field) {
	_ = h.flush() // exiting regardless; the local output already holds the line
	h.exit(1)
}

// errorReporter is the OpenTelemetry error handler: one line a minute at most,
// written to the local-only logger so a failing export cannot log into itself.
// Times are measured from start on the monotonic clock, so a wall-clock step
// cannot silence it.
type errorReporter struct {
	local *zap.Logger
	now   func() time.Time
	start time.Time
	last  atomic.Int64 // nanoseconds after start of the last report, plus one; 0 means never
}

func newErrorReporter(local *zap.Logger, now func() time.Time) *errorReporter {
	return &errorReporter{local: local, now: now, start: now()}
}

func (e *errorReporter) Handle(err error) {
	at := int64(e.now().Sub(e.start)) + 1
	prev := e.last.Load()
	if prev != 0 && time.Duration(at-prev) < errorReportInterval {
		return
	}
	if !e.last.CompareAndSwap(prev, at) {
		return
	}
	e.local.Warn("log_export_failed", zap.Error(err))
}
