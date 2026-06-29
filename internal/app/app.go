// Package app assembles the workspace service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/workspace), the
// embeddable library (workspaceserver), and the e2e tests, so all three
// exercise the same middleware chain and handler registration.
package app

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	"go.uber.org/zap"

	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/internal/config"
	connecthandler "github.com/elloloop/workspace/internal/connect"
	"github.com/elloloop/workspace/internal/middleware"
	"github.com/elloloop/workspace/internal/service"
)

// Deps are the injectable dependencies needed to build the handler. The full
// service configuration is the single canonical *config.Config (the same struct
// the env loader fills and an embedder passes), NOT re-declared field by field;
// the remaining fields are runtime dependencies that cannot be expressed as env
// config (the persistence driver, the logger, and the optional audit sinks).
type Deps struct {
	// Config is the single source of truth for all service knobs.
	Config *config.Config
	// Repo is the persistence driver.
	Repo service.Repository
	// Logger is the structured logger; nil becomes a no-op.
	Logger *zap.Logger
	// DecisionLogger, when non-nil, receives an audit record for every
	// Check/CheckSet decision. The caller owns its lifecycle (Close).
	DecisionLogger service.DecisionLogger
	// AuditLogger, when non-nil, receives an append-only audit record for every
	// relation-tuple change and admin mutation. The caller owns its lifecycle.
	AuditLogger service.AuditLogger
}

// New builds the full HTTP handler: the four Connect services plus health
// routes, wrapped in the recover → CORS → service-auth middleware chain. It
// also seeds the default project so the deployment's default shard is always
// resolvable.
func New(ctx context.Context, d Deps) (http.Handler, error) {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg := d.Config
	if cfg == nil {
		cfg = &config.Config{}
	}
	opts := []service.Option{
		service.WithMaxListObjects(cfg.MaxListObjects),
		service.WithMaxExpandNodes(cfg.MaxExpandNodes),
		service.WithMaxCheckReads(cfg.MaxCheckReads),
		service.WithDataRegion(cfg.DataRegion),
		service.WithLogger(logger),
	}
	if d.DecisionLogger != nil {
		opts = append(opts, service.WithDecisionLogger(d.DecisionLogger))
	}
	if d.AuditLogger != nil {
		opts = append(opts, service.WithAuditLogger(d.AuditLogger))
	}
	svc := service.New(d.Repo, nil, nil, opts...)
	if err := svc.EnsureDefaultProject(ctx, cfg.DefaultProjectID); err != nil {
		return nil, err
	}
	h := connecthandler.NewHandler(svc, cfg.DefaultProjectID, cfg.DefaultTenantID, cfg.AdminAPISecret, cfg.MaxBatchCheckItems, cfg.AdminRateLimitPerMinute, cfg.TenantRateLimitPerMinute)

	mux := http.NewServeMux()
	// Install the engine-backstop collector centrally on every service handler, so
	// EVERY engine evaluation — data-plane and product-surface alike — feeds
	// authz_eval_backstop_total, counted once per reason per request, and any
	// future engine-check entrypoint is covered without a per-handler install.
	hOpts := connect.WithInterceptors(h.Interceptors()...)
	wsPath, wsHandler := workspacev1connect.NewWorkspaceServiceHandler(h, hOpts)
	mux.Handle(wsPath, wsHandler)
	grpPath, grpHandler := workspacev1connect.NewGroupServiceHandler(h, hOpts)
	mux.Handle(grpPath, grpHandler)
	azPath, azHandler := workspacev1connect.NewAuthzServiceHandler(h, hOpts)
	mux.Handle(azPath, azHandler)
	adminPath, adminHandler := workspacev1connect.NewAdminServiceHandler(h, hOpts)
	mux.Handle(adminPath, adminHandler)
	seatPath, seatHandler := workspacev1connect.NewSeatServiceHandler(h, hOpts)
	mux.Handle(seatPath, seatHandler)

	health := middleware.Health()
	mux.Handle("/healthz", health)
	mux.Handle("/readyz", health)

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.CORS(cfg.AllowedOrigins),
		middleware.ServiceAuth(cfg.ServiceAuthTokens, cfg.ServiceCredentials, logger),
	), nil
}
