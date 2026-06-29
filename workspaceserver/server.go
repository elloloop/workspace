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
	"github.com/elloloop/workspace/internal/auditlog"
	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/internal/decisionlog"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// Config is the service configuration an embedder passes. It is the SAME
// canonical struct the container's env loader fills (config.Config), aliased
// here so the embeddable surface and the env path can never drift apart — add a
// knob once, in config.Config, and both paths get it. An embedder simply leaves
// the container-only fields (ports, PostgresDSN, …) at their zero values.
type Config = config.Config

// Options configures New. Repo defaults to an in-memory store; Logger defaults
// to a no-op. Config carries the service knobs; the other fields are runtime
// dependencies that are not env-expressible.
type Options struct {
	Logger *zap.Logger
	Repo   service.Repository
	Config Config
}

// OptionsFromEnv builds Options from the process environment (GATEWAY_*),
// validating it. It is the one place the container binary turns env into
// Options; an embedder constructs Options directly instead.
func OptionsFromEnv() (Options, error) {
	cfg, err := config.Load()
	if err != nil {
		return Options{}, err
	}
	return Options{Config: *cfg}, nil
}

// Server is the assembled workspace service.
type Server struct {
	handler     http.Handler
	decisionLog *decisionlog.ZapLogger
	auditLog    *auditlog.ZapLogger
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
	// Validate the instance region on the embeddable path too — the env path
	// validates in config.Validate, but an embedder builds Options.Config
	// directly and would otherwise bypass it (a typo'd region silently fails
	// closed for every matching project). One shared validator on every entry.
	if err := service.ValidateRegion(opts.Config.DataRegion); err != nil {
		return nil, err
	}
	// Copy the config so we can default a field, and hand app a pointer to the
	// single canonical struct rather than re-listing every knob.
	cfg := opts.Config
	if cfg.DefaultProjectID == "" {
		cfg.DefaultProjectID = config.DefaultProjectIDFallback
	}
	deps := app.Deps{Config: &cfg, Repo: repo, Logger: logger}
	// Only construct (and only then set the interface field) when enabled, so a
	// disabled log leaves a genuinely nil interface — not a typed nil that would
	// look non-nil to app.New.
	var dl *decisionlog.ZapLogger
	if cfg.DecisionLog {
		dl = decisionlog.NewZap(logger, 0)
		deps.DecisionLogger = dl
	}
	var al *auditlog.ZapLogger
	if cfg.AuditLog {
		al = auditlog.NewZap(logger, 0)
		deps.AuditLogger = al
	}
	handler, err := app.New(ctx, deps)
	if err != nil {
		if dl != nil {
			dl.Close()
		}
		if al != nil {
			al.Close()
		}
		return nil, err
	}
	return &Server{handler: handler, decisionLog: dl, auditLog: al}, nil
}

// Handler returns the service's HTTP handler; mount it on an h2c/HTTP-2 server.
func (s *Server) Handler() http.Handler { return s.handler }

// Close releases background resources (the decision-log drain goroutine). It is
// idempotent and a no-op when the decision log is disabled.
func (s *Server) Close() {
	if s.decisionLog != nil {
		s.decisionLog.Close()
	}
	if s.auditLog != nil {
		s.auditLog.Close()
	}
}
