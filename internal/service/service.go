package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/elloloop/workspace/pkg/authz"
)

// Principal is the authenticated caller, resolved from the verified JWT by
// the auth middleware: the user every decision is made against, the project
// (configuration/model shard) and the tenant (data-isolation shard within the
// project) the request operates in. An empty TenantID is the default tenant.
type Principal struct {
	UserID    string
	ProjectID string
	TenantID  string
}

// Service implements the product surface (workspaces, groups, invitations)
// on top of the Repository and the authz Engine. It is transport-agnostic;
// the Connect handlers translate to/from proto and map errors to codes.
type Service struct {
	repo     Repository
	engine   *authz.Engine
	resolver *modelResolver
	now      func() time.Time
	newID    func() string
}

// New builds a Service. clock and idgen are injectable for deterministic
// tests; nil falls back to time.Now and a random hex id. The engine resolves
// each project's authorization model from the repository, falling back to the
// built-in default for unconfigured projects.
func New(repo Repository, clock func() time.Time, idgen func() string) *Service {
	if clock == nil {
		clock = time.Now
	}
	if idgen == nil {
		idgen = func() string { return randHex(16) }
	}
	resolver := newModelResolver(repo)
	return &Service{
		repo:     repo,
		engine:   authz.NewEngine(resolver, repo),
		resolver: resolver,
		now:      clock,
		newID:    idgen,
	}
}

// Engine exposes the authz engine for the AuthzService handler.
func (s *Service) Engine() *authz.Engine { return s.engine }

// Repo exposes the repository for the AuthzService handler's raw read/write.
func (s *Service) Repo() Repository { return s.repo }

// allowed is a thin wrapper over the engine for the common workspace check.
func (s *Service) allowed(ctx context.Context, p Principal, workspaceID string, rel Role) (bool, error) {
	return s.engine.Check(ctx, p.ProjectID, p.TenantID, "workspace", workspaceID, string(rel), p.UserID)
}

// requireWorkspace loads a workspace and confirms the caller holds at least
// the given relation on it, returning a wire-mappable error otherwise.
func (s *Service) requireWorkspace(ctx context.Context, p Principal, workspaceID string, rel Role) (*Workspace, error) {
	w, err := s.repo.GetWorkspace(ctx, p.ProjectID, p.TenantID, workspaceID)
	if err != nil {
		return nil, err
	}
	ok, err := s.allowed(ctx, p, workspaceID, rel)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: requires %s on workspace", ErrPermissionDenied, rel)
	}
	return w, nil
}

// ── helpers ──────────────────────────────────────────────────────────────

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugInvalid.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "ws"
	}
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	return s
}

// userTuple builds a concrete-user relation tuple.
func userTuple(ns, obj, rel, userID string) authz.Tuple {
	return authz.Tuple{Namespace: ns, ObjectID: obj, Relation: rel, Subject: authz.Subject{UserID: userID}}
}
