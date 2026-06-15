// Package app assembles the workspace service HTTP handler from injected
// dependencies. It is shared by the production binary (cmd/workspace), the
// embeddable library (workspaceserver), and the e2e tests, so all three
// exercise the same middleware chain and handler registration.
package app

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/workspaces/gen/go/workspace/workspaceconnect"
	connecthandler "github.com/elloloop/workspaces/internal/connect"
	"github.com/elloloop/workspaces/internal/middleware"
	"github.com/elloloop/workspaces/internal/service"
	"github.com/elloloop/workspaces/pkg/jwt"
)

// Deps are the injectable dependencies needed to build the handler.
type Deps struct {
	Logger           *zap.Logger
	Repo             service.Repository
	Verifier         jwt.Verifier
	DefaultProjectID string
	AllowedOrigins   []string
}

// New builds the full HTTP handler: the three Connect services plus health
// routes, wrapped in the recover → CORS → auth middleware chain.
func New(d Deps) http.Handler {
	logger := d.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	svc := service.New(d.Repo, nil, nil)
	h := connecthandler.NewHandler(svc)

	mux := http.NewServeMux()
	wsPath, wsHandler := workspaceconnect.NewWorkspaceServiceHandler(h)
	mux.Handle(wsPath, wsHandler)
	grpPath, grpHandler := workspaceconnect.NewGroupServiceHandler(h)
	mux.Handle(grpPath, grpHandler)
	azPath, azHandler := workspaceconnect.NewAuthzServiceHandler(h)
	mux.Handle(azPath, azHandler)

	health := middleware.Health()
	mux.Handle("/healthz", health)
	mux.Handle("/readyz", health)

	return middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.CORS(d.AllowedOrigins),
		middleware.Auth(d.Verifier, d.DefaultProjectID, logger),
	)
}
