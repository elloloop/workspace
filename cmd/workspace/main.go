// Command workspace is the workspace authorization service container entry
// point. It loads configuration from the environment, selects a token
// verifier and storage driver, and serves the Connect-RPC handler over h2c
// plus a Prometheus metrics listener. All wiring lives in
// github.com/elloloop/workspace/workspaceserver so an embedder runs the
// same code path this binary does.
//
// `workspace migrate` runs pending Postgres migrations and exits.
package main

import (
	"context"
	"errors"
	"fmt"
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
		code := runMigrate(cfg, logger)
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

	srv, err := workspaceserver.New(ctx, workspaceserver.Options{
		Logger: logger,
		Repo:   repo,
		Config: workspaceserver.Config{
			DefaultProjectID:  cfg.DefaultProjectID,
			DefaultTenantID:   cfg.DefaultTenantID,
			AllowedOrigins:    cfg.AllowedOrigins,
			ServiceAuthTokens: cfg.ServiceAuthTokens,
			AdminAPISecret:    cfg.AdminAPISecret,
			MaxListObjects:    cfg.MaxListObjects,
			MaxExpandNodes:    cfg.MaxExpandNodes,
		},
	})
	if err != nil {
		logger.Fatal("server_init_failed", zap.Error(err))
	}

	logger.Info("workspace_service_starting",
		zap.Int("connect_port", cfg.ConnectPort),
		zap.Int("metrics_port", cfg.MetricsPort),
		zap.String("default_project", cfg.DefaultProjectID),
		zap.Bool("postgres", cfg.PostgresDSN != ""),
		zap.Bool("service_auth", len(cfg.ServiceAuthTokens) > 0))

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
	store, err := postgres.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		return nil, nil, err
	}
	if cfg.PostgresAutoMigrate {
		if err := store.Migrate(ctx); err != nil {
			store.Close()
			return nil, nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return store, store.Close, nil
}

func runMigrate(cfg *config.Config, logger *zap.Logger) int {
	if cfg.PostgresDSN == "" {
		logger.Error("migrate_requires_postgres", zap.String("hint", "set GATEWAY_POSTGRES_DSN"))
		return 2
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		logger.Error("migrate_open_failed", zap.Error(err))
		return 1
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		logger.Error("migrate_failed", zap.Error(err))
		return 1
	}
	logger.Info("migrate_complete")
	return 0
}
