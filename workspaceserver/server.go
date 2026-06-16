// Package workspaceserver is the embeddable workspace service: it assembles
// the HTTP handler from options so the container binary (cmd/workspace) and
// any host Go server run the exact same code path. The e2e tests build a
// Server with the in-memory driver and a test verifier.
package workspaceserver

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/workspace/internal/app"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// Config is the embedder-facing subset of service configuration.
type Config struct {
	DefaultProjectID string
	AllowedOrigins   []string
	// ServiceAuthTokens are the accepted service credentials. Empty disables
	// the requirement (trusted network / mesh).
	ServiceAuthTokens []string
	// AdminAPISecret gates the AdminService (project configuration). Empty
	// disables the admin RPCs.
	AdminAPISecret string
}

// Options configures New. Repo defaults to an in-memory store; Logger
// defaults to a no-op.
type Options struct {
	Logger *zap.Logger
	Repo   service.Repository
	Config Config
}

// Server is the assembled workspace service.
type Server struct {
	handler http.Handler
}

// New builds the server.
func New(ctx context.Context, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	repo := opts.Repo
	if repo == nil {
		repo = memory.New()
	}
	projectID := opts.Config.DefaultProjectID
	if projectID == "" {
		projectID = "default"
	}
	handler, err := app.New(ctx, app.Deps{
		Logger:            logger,
		Repo:              repo,
		DefaultProjectID:  projectID,
		AllowedOrigins:    opts.Config.AllowedOrigins,
		ServiceAuthTokens: opts.Config.ServiceAuthTokens,
		AdminAPISecret:    opts.Config.AdminAPISecret,
	})
	if err != nil {
		return nil, err
	}
	return &Server{handler: handler}, nil
}

// Handler returns the service's HTTP handler; mount it on an h2c/HTTP-2 server.
func (s *Server) Handler() http.Handler { return s.handler }
