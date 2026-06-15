// Package workspaceserver is the embeddable workspace service: it assembles
// the HTTP handler from options so the container binary (cmd/workspace) and
// any host Go server run the exact same code path. The e2e tests build a
// Server with the in-memory driver and a test verifier.
package workspaceserver

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/workspaces/internal/app"
	"github.com/elloloop/workspaces/internal/repo/memory"
	"github.com/elloloop/workspaces/internal/service"
	"github.com/elloloop/workspaces/pkg/jwt"
)

// Config is the embedder-facing subset of service configuration.
type Config struct {
	DefaultProjectID string
	AllowedOrigins   []string
}

// Options configures New. Verifier is required; Repo defaults to an
// in-memory store; Logger defaults to a no-op.
type Options struct {
	Logger   *zap.Logger
	Verifier jwt.Verifier
	Repo     service.Repository
	Config   Config
}

// Server is the assembled workspace service.
type Server struct {
	handler http.Handler
}

// New builds the server. It returns an error if no token verifier is given.
func New(_ context.Context, opts Options) (*Server, error) {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	if opts.Verifier == nil {
		return nil, errMissingVerifier
	}
	repo := opts.Repo
	if repo == nil {
		repo = memory.New()
	}
	projectID := opts.Config.DefaultProjectID
	if projectID == "" {
		projectID = "default"
	}
	handler := app.New(app.Deps{
		Logger:           logger,
		Repo:             repo,
		Verifier:         opts.Verifier,
		DefaultProjectID: projectID,
		AllowedOrigins:   opts.Config.AllowedOrigins,
	})
	return &Server{handler: handler}, nil
}

// Handler returns the service's HTTP handler; mount it on an h2c/HTTP-2 server.
func (s *Server) Handler() http.Handler { return s.handler }
