package logging

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/proto"
)

// collector is a fake OTLP/HTTP receiver that keeps every request it is sent.
type collector struct {
	mu       sync.Mutex
	paths    []string
	requests []*collogs.ExportLogsServiceRequest
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req := &collogs.ExportLogsServiceRequest{}
	if err := proto.Unmarshal(body, req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.paths = append(c.paths, r.URL.Path)
	c.requests = append(c.requests, req)
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-protobuf")
}

// records returns every received record and the resource attributes they came with.
func (c *collector) records() ([]*logspb.LogRecord, map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var recs []*logspb.LogRecord
	attrs := map[string]string{}
	for _, req := range c.requests {
		for _, rl := range req.GetResourceLogs() {
			for _, kv := range rl.GetResource().GetAttributes() {
				attrs[kv.GetKey()] = kv.GetValue().GetStringValue()
			}
			for _, sl := range rl.GetScopeLogs() {
				recs = append(recs, sl.GetLogRecords()...)
			}
		}
	}
	return recs, attrs
}

func (c *collector) bodies() []string {
	recs, _ := c.records()
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.GetBody().GetStringValue())
	}
	return out
}

// startCollector serves a fake collector and points the export at it.
func startCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{}
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	t.Setenv(EndpointEnv, srv.URL)
	return c
}

// clearOTELEnv unsets every variable the export reads, restoring them afterwards.
func clearOTELEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		EndpointEnv, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_SERVICE_NAME", "OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_BLRP_SCHEDULE_DELAY", "OTEL_EXPORTER_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE",
		"OTEL_EXPORTER_OTLP_INSECURE", "OTEL_EXPORTER_OTLP_LOGS_INSECURE",
	} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unset %s: %v", k, err)
		}
	}
}

// testLogger builds a logger whose local output is also observed. A Fatal
// line fails the test instead of ending the test binary.
func testLogger(t *testing.T) (*Logger, *observer.ObservedLogs) {
	t.Helper()
	obs, logs := observer.New(zapcore.InfoLevel) // production's level
	l, err := newLogger(context.Background(), func(code int) { t.Errorf("unexpected exit(%d)", code) },
		zap.WrapCore(func(c zapcore.Core) zapcore.Core { return zapcore.NewTee(c, obs) }))
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	return l, logs
}

// The engine boots exactly as before when the endpoint is unset, empty or blank:
// no export is built, and every line still reaches the local output.
func TestExportOffWithoutAnEndpoint(t *testing.T) {
	for name, value := range map[string]*string{"unset": nil, "empty": ptr(""), "blank": ptr(" \t ")} {
		t.Run(name, func(t *testing.T) {
			clearOTELEnv(t)
			if value != nil {
				t.Setenv(EndpointEnv, *value)
			}
			l, logs := testLogger(t)
			if l.shutdown != nil {
				t.Fatal("export is on without an endpoint")
			}
			l.Debug("below_production_level")
			l.Info("local_only")
			if err := l.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := logs.All(); len(got) != 1 || got[0].Message != "local_only" {
				t.Fatalf("local output = %v, want the one Info line", got)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestExportDeliversRecordsWithResourceFromEnv(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	t.Setenv("OTEL_SERVICE_NAME", "workspace-under-test")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=test")

	l, logs := testLogger(t)
	l.Debug("below_the_local_level")
	l.With(zap.String("caller_id", "c1")).Warn("exported_line", zap.Int("n", 7))
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs, attrs := c.records()
	if len(c.paths) == 0 || c.paths[0] != "/v1/logs" {
		t.Fatalf("collector paths = %v, want /v1/logs", c.paths)
	}
	if got := attrs["service.name"]; got != "workspace-under-test" {
		t.Errorf("service.name = %q, want OTEL_SERVICE_NAME's value", got)
	}
	if got := attrs["deployment.environment"]; got != "test" {
		t.Errorf("deployment.environment = %q, want OTEL_RESOURCE_ATTRIBUTES's value", got)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want only the Warn line (Debug is below the local level)", len(recs))
	}
	rec := recs[0]
	if got := rec.GetBody().GetStringValue(); got != "exported_line" {
		t.Errorf("body = %q, want exported_line", got)
	}
	if got := rec.GetSeverityText(); got != "warn" {
		t.Errorf("severity = %q, want warn", got)
	}
	fields := map[string]bool{}
	for _, kv := range rec.GetAttributes() {
		fields[kv.GetKey()] = true
	}
	if !fields["caller_id"] || !fields["n"] {
		t.Errorf("attributes = %v, want caller_id and n", rec.GetAttributes())
	}
	if got := logs.FilterMessage("exported_line").Len(); got != 1 {
		t.Errorf("local output has %d exported_line entries, want 1 (the export is beside it, not instead)", got)
	}
}

func TestExportDefaultsServiceName(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	l, _ := testLogger(t)
	l.Info("line")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, attrs := c.records(); attrs["service.name"] != defaultServiceName {
		t.Errorf("service.name = %q, want %q", attrs["service.name"], defaultServiceName)
	}
}

// An unreachable collector never blocks a caller and never loses the local
// output; a failed background export is logged as log_export_failed, and the
// failed final flush is returned by Close. (A hanging collector, the case the
// flush budget exists for, is TestCloseIsBoundedWhenTheCollectorHangs.)
func TestUnreachableCollector(t *testing.T) {
	clearOTELEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	t.Setenv(EndpointEnv, "http://"+addr)
	t.Setenv("OTEL_BLRP_SCHEDULE_DELAY", "50") // milliseconds: export in the background soon

	l, logs := testLogger(t)
	const lines = 500
	start := time.Now()
	for i := range lines {
		l.Info("while_unreachable", zap.Int("i", i))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("logging %d lines took %v, want the export never to block a caller", lines, elapsed)
	}
	deadline := time.Now().Add(5 * time.Second)
	for logs.FilterMessage("log_export_failed").Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a failed background export was not logged as log_export_failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	l.Info("before_close")
	if err := l.Close(); err == nil {
		t.Error("Close: want the failed flush reported, got nil")
	}
	if got := logs.FilterMessage("while_unreachable").Len(); got == 0 {
		t.Error("local output lost the lines while the collector was unreachable")
	}
}

// A malformed OTEL_RESOURCE_ATTRIBUTES entry never stops the engine from
// booting: the export stays on with the attributes that parsed, and the bad
// entry is reported.
func TestMalformedResourceAttributesStillBoots(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	t.Setenv("OTEL_SERVICE_NAME", "workspace-under-test")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=test,no-equals-sign")

	l, logs := testLogger(t)
	if l.shutdown == nil {
		t.Fatal("export is off; want it on with the attributes that parsed")
	}
	l.Info("booted")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if logs.FilterMessage("log_export_failed").Len() == 0 {
		t.Error("the malformed attribute was not reported as log_export_failed")
	}
	if got := c.bodies(); len(got) != 1 || got[0] != "booted" {
		t.Fatalf("collector got %v, want the line", got)
	}
	if _, attrs := c.records(); attrs["service.name"] != "workspace-under-test" {
		t.Errorf("service.name = %q, want the parsed OTEL_SERVICE_NAME kept", attrs["service.name"])
	}
}

// An exporter the SDK refuses to build (here a TLS certificate configured for
// a plain-http endpoint) never stops the engine from booting: logging falls
// back to stderr only, and the reason is reported.
func TestExporterErrorFallsBackToStderrOnly(t *testing.T) {
	clearOTELEnv(t)
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsSrv.Close)
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	t.Setenv(EndpointEnv, "http://127.0.0.1:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", certFile)

	l, logs := testLogger(t)
	if l.shutdown != nil {
		t.Fatal("export is on; want the stderr-only fallback")
	}
	l.Info("booted")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if logs.FilterMessage("booted").Len() != 1 {
		t.Fatal("local output lost the line")
	}
	if logs.FilterMessage("log_export_failed").Len() == 0 {
		t.Error("the exporter error was not reported as log_export_failed")
	}
}

// zap's production sampler sits outside the tee: a burst of one message keeps
// the same lines on stderr and at the collector.
func TestSamplingKeepsTheSameLinesInBothOutputs(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	l, logs := testLogger(t)
	const burst = 300
	for range burst {
		l.Info("burst")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	local, exported := logs.FilterMessage("burst").Len(), len(c.bodies())
	if local >= burst {
		t.Fatalf("local kept %d of %d identical lines, want the production sampler to drop some", local, burst)
	}
	if exported != local {
		t.Fatalf("collector got %d lines, stderr kept %d; want the same sample", exported, local)
	}
}

// A bad endpoint never stops the engine from booting: the logger is built, the
// local output works, and the problem is logged as log_export_failed.
func TestBadEndpointStillBoots(t *testing.T) {
	for name, value := range map[string]string{
		"no scheme or host": "::not a url",
		"unclosed IPv6":     "http://[::1",
	} {
		t.Run(name, func(t *testing.T) {
			clearOTELEnv(t)
			t.Setenv(EndpointEnv, value)
			l, logs := testLogger(t)
			l.flushTimeout = 300 * time.Millisecond
			l.Info("booted")
			_ = l.Close() // the flush to wherever the SDK fell back to may fail; it must return
			if logs.FilterMessage("booted").Len() != 1 {
				t.Fatal("local output lost the line")
			}
			if logs.FilterMessage("log_export_failed").Len() == 0 {
				t.Errorf("the bad endpoint %q was not reported as log_export_failed", value)
			}
		})
	}
}

func TestCloseIsBoundedWhenTheCollectorHangs(t *testing.T) {
	clearOTELEnv(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	t.Setenv(EndpointEnv, srv.URL)

	l, _ := testLogger(t)
	l.flushTimeout = 200 * time.Millisecond
	l.Info("never_delivered")
	start := time.Now()
	err := l.Close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close took %v, want it bounded by the flush budget", elapsed)
	}
	if err == nil {
		t.Fatal("Close: want the flush deadline reported, got nil")
	}
}

// The default batch interval is longer than this test, so the line can only
// reach the collector through Close's flush; a second Close is harmless.
func TestCloseFlushesQueuedLines(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	l, _ := testLogger(t)
	l.Info("queued_line")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := c.bodies(); len(got) != 1 || got[0] != "queued_line" {
		t.Fatalf("collector got %v, want the queued line", got)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// A Fatal line reaches the collector before the process exits.
func TestFatalFlushesThenExits(t *testing.T) {
	clearOTELEnv(t)
	c := startCollector(t)
	type exitCall struct {
		code      int
		delivered []string // what the collector held when exit was called
	}
	var exits []exitCall
	l, err := newLogger(context.Background(), func(code int) {
		exits = append(exits, exitCall{code: code, delivered: c.bodies()})
	})
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	// Check+Write is Fatal's own path; static analysis treats Fatal as never returning.
	l.Check(zapcore.FatalLevel, "config_invalid").Write()
	if len(exits) != 1 || exits[0].code != 1 {
		t.Fatalf("exits = %+v, want one exit with code 1", exits)
	}
	if got := exits[0].delivered; len(got) != 1 || got[0] != "config_invalid" {
		t.Fatalf("at exit the collector held %v, want the Fatal line already delivered", got)
	}
}

func TestErrorReporterWritesAtMostOnceAMinute(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	now := time.Unix(1_000, 0)
	r := newErrorReporter(zap.New(core), func() time.Time { return now })

	r.Handle(errors.New("first"))
	r.Handle(errors.New("suppressed"))
	now = now.Add(errorReportInterval)
	r.Handle(errors.New("after a minute"))

	entries := logs.FilterMessage("log_export_failed").All()
	if len(entries) != 2 {
		t.Fatalf("got %d reports, want 2", len(entries))
	}
	if got := entries[1].ContextMap()["error"]; got != "after a minute" {
		t.Errorf("second report error = %v, want the error after a minute", got)
	}
}
