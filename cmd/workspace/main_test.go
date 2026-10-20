package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/internal/logging"
	"github.com/elloloop/workspace/internal/repo/postgres"
	"go.uber.org/zap/zaptest"
)

// TestMigrateCommandFlushesTheExport pins that the migrate command's lines reach
// the log export before the process exits, on its usage and its failure paths.
// The default batch interval is longer than this test, so a line can only reach
// the collector through the flush.
func TestMigrateCommandFlushesTheExport(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantLine string
	}{
		{name: "usage error", args: []string{"--contrct"}, wantCode: 2, wantLine: "migrate_usage"},
		{name: "no postgres", args: nil, wantCode: 2, wantLine: "migrate_requires_postgres"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var received strings.Builder
			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				received.Write(body)
				mu.Unlock()
			}))
			t.Cleanup(srv.Close)
			// A logs-specific endpoint would win over ours, and a short schedule
			// delay would deliver the line without the flush this test is about.
			for _, k := range []string{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_BLRP_SCHEDULE_DELAY"} {
				t.Setenv(k, "")
				if err := os.Unsetenv(k); err != nil {
					t.Fatalf("unset %s: %v", k, err)
				}
			}
			t.Setenv(logging.EndpointEnv, srv.URL)

			logs, err := logging.New(context.Background())
			if err != nil {
				t.Fatalf("logging.New: %v", err)
			}
			if code := migrateCommand(tc.args, &config.Config{}, logs); code != tc.wantCode {
				t.Fatalf("migrateCommand(%v) = %d, want %d", tc.args, code, tc.wantCode)
			}
			mu.Lock()
			defer mu.Unlock()
			if !strings.Contains(received.String(), tc.wantLine) {
				t.Fatalf("the collector did not receive %q before migrate returned", tc.wantLine)
			}
		})
	}
}

// TestLogBootMigrate pins the boot-path auto-migrate error classification: a
// lock-held failure is transient (does NOT abort startup), a context deadline
// and any genuine schema/DDL error abort. Uses errors.Is via wrapped errors to
// match the real Migrate call paths.
func TestLogBootMigrate(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantAbort bool
	}{
		{name: "success does not abort", err: nil},
		{
			name:      "lock held does not abort",
			err:       fmt.Errorf("migrate: %w", postgres.ErrMigrationLockHeld),
			wantAbort: false,
		},
		{
			name:      "boot timeout aborts",
			err:       fmt.Errorf("expand workspaces: %w", context.DeadlineExceeded),
			wantAbort: true,
		},
		{
			name:      "schema error aborts",
			err:       errors.New("expand relation_tuples: column does not exist"),
			wantAbort: true,
		},
	}
	logger := zaptest.NewLogger(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := logBootMigrate(logger, tc.err); got != tc.wantAbort {
				t.Fatalf("logBootMigrate(%v) abort=%v, want %v", tc.err, got, tc.wantAbort)
			}
		})
	}
}

// TestParseMigrateArgs pins the flag-based migrate subcommand: expand by default,
// --contract / -contract selects contract, and an unknown/typo'd or extra arg
// errors (so it cannot silently fall through to expand).
func TestParseMigrateArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantContract bool
		wantErr      bool
	}{
		{name: "no args is expand", args: nil},
		{name: "double dash contract", args: []string{"--contract"}, wantContract: true},
		{name: "single dash contract", args: []string{"-contract"}, wantContract: true},
		{name: "explicit false", args: []string{"--contract=false"}},
		{name: "typo errors", args: []string{"--contrct"}, wantErr: true},
		{name: "unknown flag errors", args: []string{"--expand"}, wantErr: true},
		{name: "positional arg errors", args: []string{"contract"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contract, err := parseMigrateArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMigrateArgs(%v): want error, got contract=%v", tc.args, contract)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMigrateArgs(%v): unexpected error: %v", tc.args, err)
			}
			if contract != tc.wantContract {
				t.Fatalf("parseMigrateArgs(%v) contract=%v, want %v", tc.args, contract, tc.wantContract)
			}
		})
	}
}
