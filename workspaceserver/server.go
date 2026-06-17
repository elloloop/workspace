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
	"github.com/elloloop/workspace/internal/decisionlog"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// Config is the embedder-facing subset of service configuration.
type Config struct {
	DefaultProjectID string
	// DefaultTenantID is applied when a request omits tenant_id.
	DefaultTenantID string
	AllowedOrigins  []string
	// ServiceAuthTokens are the accepted service credentials. Empty disables
	// the requirement (trusted network / mesh).
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
	// MaxBatchCheckItems caps a single BatchCheck request; non-positive uses
	// the configured default.
	MaxBatchCheckItems int
	// AdminRateLimitPerMinute throttles the admin API per caller; non-positive
	// disables the limiter.
	AdminRateLimitPerMinute int
	// TenantRateLimitPerMinute throttles authz RPCs per (project, tenant);
	// non-positive disables the limiter.
	TenantRateLimitPerMinute int
	// DecisionLog enables the async authorization decision audit log. Default
	// false. When enabled, call Server.Close on shutdown to flush it.
	DecisionLog bool
	// AuditLog enables the async tuple-change + admin-mutation audit log.
	// Default false. When enabled, call Server.Close on shutdown to flush it.
	AuditLog bool
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
	projectID := opts.Config.DefaultProjectID
	if projectID == "" {
		projectID = "default"
	}
	deps := app.Deps{
		Logger:                   logger,
		Repo:                     repo,
		DefaultProjectID:         projectID,
		DefaultTenantID:          opts.Config.DefaultTenantID,
		AllowedOrigins:           opts.Config.AllowedOrigins,
		ServiceAuthTokens:        opts.Config.ServiceAuthTokens,
		AdminAPISecret:           opts.Config.AdminAPISecret,
		MaxListObjects:           opts.Config.MaxListObjects,
		MaxExpandNodes:           opts.Config.MaxExpandNodes,
		MaxBatchCheckItems:       opts.Config.MaxBatchCheckItems,
		AdminRateLimitPerMinute:  opts.Config.AdminRateLimitPerMinute,
		TenantRateLimitPerMinute: opts.Config.TenantRateLimitPerMinute,
	}
	// Only construct (and only then set the interface field) when enabled, so a
	// disabled log leaves a genuinely nil DecisionLogger interface — not a
	// typed nil that would look non-nil to app.New.
	var dl *decisionlog.ZapLogger
	if opts.Config.DecisionLog {
		dl = decisionlog.NewZap(logger, 0)
		deps.DecisionLogger = dl
	}
	var al *auditlog.ZapLogger
	if opts.Config.AuditLog {
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
