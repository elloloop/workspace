// Command workspace is the workspace authorization service container entry
// point. It loads configuration from the environment, selects a token
// verifier and storage driver, and serves the Connect-RPC handler over h2c
// plus a Prometheus metrics listener. All wiring lives in
// github.com/elloloop/workspace/workspaceserver so an embedder runs the
// same code path this binary does.
//
// `workspace migrate` runs the expand phase (idempotent; build composite keys
// as concurrent unique indexes, old PK kept) and exits; `workspace migrate
// --contract` runs the contract phase (promote those indexes to PRIMARY KEY,
// drop the old PK) — a deliberate step run only after the whole fleet is on the
// new binary. See the README two-phase migration runbook.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/repo/postgres"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/workspaceserver"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("config_invalid", zap.Error(err))
	}

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		contract, err := parseMigrateArgs(os.Args[2:])
		if err != nil {
			logger.Error("migrate_usage", zap.Error(err))
			_ = logger.Sync()
			os.Exit(2)
		}
		code := runMigrate(cfg, logger, contract)
		_ = logger.Sync()
		os.Exit(code)
	}
	defer func() { _ = logger.Sync() }()

	ctx := context.Background()
	repo, closeRepo, err := buildRepo(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("repo_init_failed", zap.Error(err))
	}
	defer closeRepo()

	// Thread the loaded config straight through — no field-by-field copy. The
	// container owns the repo lifecycle, so it passes the built repo + logger;
	// the env-only knobs (ports, DSN) it consumes itself below.
	srv, err := workspaceserver.New(ctx, workspaceserver.Options{
		Logger: logger,
		Repo:   repo,
		Config: *cfg,
	})
	if err != nil {
		logger.Fatal("server_init_failed", zap.Error(err))
	}
	defer srv.Close()

	logger.Info("workspace_service_starting",
		zap.Int("connect_port", cfg.ConnectPort),
		zap.Int("metrics_port", cfg.MetricsPort),
		zap.String("default_project", cfg.DefaultProjectID),
		zap.Bool("postgres", cfg.PostgresDSN != ""),
		zap.Bool("service_auth", len(cfg.ServiceAuthTokens) > 0))

	// Log the configured service-credential routing (NAME + project pin only —
	// never the token) so an operator can eyeball a mistyped pin before it
	// silently mis-routes an integration's writes.
	for _, c := range cfg.ServiceCredentials {
		logger.Info("service_credential_configured",
			zap.String("caller", c.Name),
			zap.String("pinned_project", c.ProjectID))
	}

	connectServer := newHTTPServer(fmt.Sprintf(":%d", cfg.ConnectPort),
		http.MaxBytesHandler(srv.Handler(), cfg.HTTPMaxBodyBytes))
	// Serve cleartext HTTP/2 (h2c) alongside HTTP/1.1 so gRPC clients work
	// behind a TLS-terminating proxy without per-connection upgrade plumbing.
	connectServer.Protocols = new(http.Protocols)
	connectServer.Protocols.SetHTTP1(true)
	connectServer.Protocols.SetUnencryptedHTTP2(true)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := newHTTPServer(fmt.Sprintf(":%d", cfg.MetricsPort), metricsMux)

	serverErr := make(chan error, 2)
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("metrics: %w", err)
		}
	}()
	go func() {
		logger.Info("workspace_service_started", zap.Int("port", cfg.ConnectPort))
		if err := connectServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("connect: %w", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	select {
	case sig := <-sigCh:
		logger.Info("workspace_service_shutting_down", zap.String("signal", sig.String()))
	case err := <-serverErr:
		logger.Error("server_failed_early", zap.Error(err))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = connectServer.Shutdown(shutdownCtx)
	_ = metricsServer.Shutdown(shutdownCtx)
	logger.Info("shutdown_complete")
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// buildRepo selects the storage driver: postgres when a DSN is set
// (running migrations first if auto-migrate is on), otherwise in-memory.
func buildRepo(ctx context.Context, cfg *config.Config, logger *zap.Logger) (service.Repository, func(), error) {
	if cfg.PostgresDSN == "" {
		logger.Warn("using_in_memory_store", zap.String("reason", "GATEWAY_POSTGRES_DSN unset"))
		return memory.New(), func() {}, nil
	}
	store, err := postgres.Open(ctx, cfg.PostgresDSN, postgres.WithLogger(logger))
	if err != nil {
		return nil, nil, err
	}
	if cfg.PostgresAutoMigrate {
		// Bound the boot-path migration so a replica blocked on the migration
		// advisory lock (e.g. behind a long out-of-band migrator) does not hang on
		// context.Background() forever.
		migrateCtx, cancel := context.WithTimeout(ctx, bootMigrateTimeout)
		defer cancel()
		logger.Info("migrate_start", zap.String("phase", "expand"), zap.Bool("boot", true))
		err := store.Migrate(migrateCtx)
		if abort := logBootMigrate(logger, err); abort {
			store.Close()
			return nil, nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return store, store.Close, nil
}

// logBootMigrate classifies the result of a boot-path (auto-migrate) expand and
// emits the matching structured event. It returns whether startup MUST abort:
//
//   - nil error: migrated; do not abort.
//   - ErrMigrationLockHeld: TRANSIENT and benign — another actor (an out-of-band
//     migrator or a sibling replica) holds the lock and is migrating the schema.
//     Do NOT abort: an expanded-but-not-contracted schema serves fine (ON
//     CONFLICT/composite-index interop), and this replica picks up the finished
//     schema once that actor completes. Emits an alertable migrate_lock_contended.
//   - context.DeadlineExceeded: the bounded boot Migrate ran out of time, almost
//     always a too-slow CONCURRENTLY build on a large existing DB. Abort, but emit
//     a distinct, actionable migrate_boot_timeout so the first occurrence is
//     diagnosable rather than a generic wrapped error.
//   - any other error: a genuine schema/DDL failure. Abort (stays fatal).
func logBootMigrate(logger *zap.Logger, err error) (abort bool) {
	switch {
	case err == nil:
		logger.Info("migrate_complete", zap.String("phase", "expand"), zap.Bool("boot", true))
		return false
	case errors.Is(err, postgres.ErrMigrationLockHeld):
		logger.Warn("migrate_lock_contended",
			zap.String("phase", "expand"),
			zap.Bool("boot", true),
			zap.String("detail", "another migration holds the lock; not migrating on this boot"),
			zap.Error(err))
		return false
	case errors.Is(err, context.DeadlineExceeded):
		logger.Error("migrate_boot_timeout",
			zap.Duration("timeout", bootMigrateTimeout),
			zap.String("hint", "set GATEWAY_POSTGRES_AUTO_MIGRATE=false and run `workspace migrate` (expand) out of band"),
			zap.Error(err))
		return true
	default:
		return true
	}
}

// bootMigrateTimeout bounds the auto-migrate-on-boot expand so a replica waiting
// on the migration lock does not hang forever: a lock-held wait resolves to a
// benign start-without-migrating, and an exceeded deadline (a too-slow
// CONCURRENTLY build) hard-exits with an actionable log. Out-of-band
// `workspace migrate` uses an unbounded context.
const bootMigrateTimeout = 3 * time.Minute

// parseMigrateArgs parses the `migrate` subcommand arguments with the flag
// package so an unknown/typo'd flag errors with a usage message (and a non-zero
// exit) instead of silently running expand. It accepts -contract / --contract.
func parseMigrateArgs(args []string) (contract bool, err error) {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	// We surface the failure via the returned error + a structured log line, so
	// suppress flag's own bare stderr usage dump.
	fs.SetOutput(io.Discard)
	c := fs.Bool("contract", false,
		"run the contract phase (promote composite indexes to PRIMARY KEY); default is expand")
	if err := fs.Parse(args); err != nil {
		return false, err
	}
	if fs.NArg() > 0 {
		return false, fmt.Errorf("unexpected argument %q (usage: workspace migrate [--contract])", fs.Arg(0))
	}
	return *c, nil
}

// runMigrate runs the expand phase (`workspace migrate`) or, when contract is
// true (`workspace migrate --contract`), the contract phase that promotes the
// composite indexes to primary keys. Contract is a deliberate, out-of-band step
// run only after the whole fleet is on the new binary.
func runMigrate(cfg *config.Config, logger *zap.Logger, contract bool) int {
	if cfg.PostgresDSN == "" {
		logger.Error("migrate_requires_postgres", zap.String("hint", "set GATEWAY_POSTGRES_DSN"))
		return 2
	}
	// Out-of-band migration: unbounded context (an operator deliberately ran this
	// and can wait out a contended boot, unlike a replica that must fail readiness).
	ctx := context.Background()
	store, err := postgres.Open(ctx, cfg.PostgresDSN, postgres.WithLogger(logger))
	if err != nil {
		logger.Error("migrate_open_failed", zap.Error(err))
		return 1
	}
	defer store.Close()
	phase := "expand"
	if contract {
		phase = "contract"
	}
	logger.Info("migrate_start", zap.String("phase", phase), zap.Bool("boot", false))
	if contract {
		if err := store.Contract(ctx); err != nil {
			logger.Error("migrate_failed", zap.String("phase", phase), zap.Error(err))
			return 1
		}
		logger.Info("migrate_complete", zap.String("phase", phase), zap.Bool("boot", false))
		return 0
	}
	if err := store.Migrate(ctx); err != nil {
		logger.Error("migrate_failed", zap.String("phase", phase), zap.Error(err))
		return 1
	}
	logger.Info("migrate_complete", zap.String("phase", phase), zap.Bool("boot", false))
	return 0
}
