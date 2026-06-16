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
	// AdminAPISecret gates the AdminService (project configuration). Empty
	// disables the admin RPCs.
	AdminAPISecret string
	// MaxListObjects caps a ListObjects candidate set; non-positive uses the
	// service default.
	MaxListObjects int
	// MaxExpandNodes caps an Expand result tree; non-positive uses the service
	// default.
	MaxExpandNodes int
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
	svc := service.New(d.Repo, nil, nil,
		service.WithMaxListObjects(d.MaxListObjects),
		service.WithMaxExpandNodes(d.MaxExpandNodes))
	if err := svc.EnsureDefaultProject(ctx, d.DefaultProjectID); err != nil {
		return nil, err
	}
	h := connecthandler.NewHandler(svc, d.DefaultProjectID, d.DefaultTenantID, d.AdminAPISecret)

	mux := http.NewServeMux()
	wsPath, wsHandler := workspacev1connect.NewWorkspaceServiceHandler(h)
	mux.Handle(wsPath, wsHandler)
	grpPath, grpHandler := workspacev1connect.NewGroupServiceHandler(h)
	mux.Handle(grpPath, grpHandler)
	azPath, azHandler := workspacev1connect.NewAuthzServiceHandler(h)
	mux.Handle(azPath, azHandler)
	adminPath, adminHandler := workspacev1connect.NewAdminServiceHandler(h)
	mux.Handle(adminPath, adminHandler)

	health := middleware.Health()
	mux.Handle("/healthz", health)
	mux.Handle("/readyz", health)

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.CORS(d.AllowedOrigins),
		middleware.ServiceAuth(d.ServiceAuthTokens, logger),
	), nil
}
