// Package app assembles the workspace service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/workspace), the
// embeddable library (workspaceserver), and the e2e tests, so all three
// exercise the same middleware chain and handler registration.
package app

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	connecthandler "github.com/elloloop/workspace/internal/connect"
	"github.com/elloloop/workspace/internal/middleware"
	"github.com/elloloop/workspace/internal/service"
)

// Deps are the injectable dependencies needed to build the handler.
type Deps struct {
	Logger           *zap.Logger
	Repo             service.Repository
	DefaultProjectID string
	// DefaultTenantID is applied when a request omits tenant_id.
	DefaultTenantID string
	AllowedOrigins  []string
	// ServiceAuthTokens are the accepted service credentials. Empty disables
	// the requirement (trusted network / mesh); see middleware.ServiceAuth.
	ServiceAuthTokens []string
	// ServiceCredentials optionally maps a credential to a named calling-service
	// identity (and project pin); additive to ServiceAuthTokens.
	ServiceCredentials []middleware.ServiceCredential
	// AdminAPISecret gates the AdminService (project configuration). Empty
	// disables the admin RPCs.
	AdminAPISecret string
	// MaxListObjects caps a ListObjects candidate set; non-positive uses the
	// service default.
	MaxListObjects int
	// MaxExpandNodes caps an Expand result tree; non-positive uses the service
	// default.
	MaxExpandNodes int
	// MaxBatchCheckItems caps a single BatchCheck request; non-positive uses
	// the configured default.
	MaxBatchCheckItems int
	// MaxCheckReads caps the store reads one engine evaluation may perform;
	// non-positive uses the service default.
	MaxCheckReads int
	// AdminRateLimitPerMinute throttles the admin API per caller; non-positive
	// disables the limiter.
	AdminRateLimitPerMinute int
	// TenantRateLimitPerMinute throttles authz RPCs per (project, tenant);
	// non-positive disables the limiter.
	TenantRateLimitPerMinute int
	// DataRegion is the region this instance serves; empty = region-agnostic.
	DataRegion string
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
	opts := []service.Option{
		service.WithMaxListObjects(d.MaxListObjects),
		service.WithMaxExpandNodes(d.MaxExpandNodes),
		service.WithMaxCheckReads(d.MaxCheckReads),
		service.WithDataRegion(d.DataRegion),
		service.WithLogger(logger),
	}
	if d.DecisionLogger != nil {
		opts = append(opts, service.WithDecisionLogger(d.DecisionLogger))
	}
	if d.AuditLogger != nil {
		opts = append(opts, service.WithAuditLogger(d.AuditLogger))
	}
	svc := service.New(d.Repo, nil, nil, opts...)
	if err := svc.EnsureDefaultProject(ctx, d.DefaultProjectID); err != nil {
		return nil, err
	}
	h := connecthandler.NewHandler(svc, d.DefaultProjectID, d.DefaultTenantID, d.AdminAPISecret, d.MaxBatchCheckItems, d.AdminRateLimitPerMinute, d.TenantRateLimitPerMinute)

	mux := http.NewServeMux()
	wsPath, wsHandler := workspacev1connect.NewWorkspaceServiceHandler(h)
	mux.Handle(wsPath, wsHandler)
	grpPath, grpHandler := workspacev1connect.NewGroupServiceHandler(h)
	mux.Handle(grpPath, grpHandler)
	azPath, azHandler := workspacev1connect.NewAuthzServiceHandler(h)
	mux.Handle(azPath, azHandler)
	adminPath, adminHandler := workspacev1connect.NewAdminServiceHandler(h)
	mux.Handle(adminPath, adminHandler)
	seatPath, seatHandler := workspacev1connect.NewSeatServiceHandler(h)
	mux.Handle(seatPath, seatHandler)

	health := middleware.Health()
	mux.Handle("/healthz", health)
	mux.Handle("/readyz", health)

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.CORS(d.AllowedOrigins),
		middleware.ServiceAuth(d.ServiceAuthTokens, d.ServiceCredentials, logger),
	), nil
}
