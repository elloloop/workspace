// Package app assembles the workspace service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/workspace), the
// embeddable library (workspaceserver), and the e2e tests, so all three
// exercise the same middleware chain and handler registration.
package app

import (
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
	AllowedOrigins   []string
	// ServiceAuthTokens are the accepted service credentials. Empty disables
	// the requirement (trusted network / mesh); see middleware.ServiceAuth.
	ServiceAuthTokens []string
}

// New builds the full HTTP handler: the three Connect services plus health
// routes, wrapped in the recover → CORS → service-auth middleware chain.
func New(d Deps) http.Handler {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	svc := service.New(d.Repo, nil, nil)
	h := connecthandler.NewHandler(svc, d.DefaultProjectID)

	mux := http.NewServeMux()
	wsPath, wsHandler := workspacev1connect.NewWorkspaceServiceHandler(h)
	mux.Handle(wsPath, wsHandler)
	grpPath, grpHandler := workspacev1connect.NewGroupServiceHandler(h)
	mux.Handle(grpPath, grpHandler)
	azPath, azHandler := workspacev1connect.NewAuthzServiceHandler(h)
	mux.Handle(azPath, azHandler)

	health := middleware.Health()
	mux.Handle("/healthz", health)
	mux.Handle("/readyz", health)

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.CORS(d.AllowedOrigins),
		middleware.ServiceAuth(d.ServiceAuthTokens, logger),
	)
}
