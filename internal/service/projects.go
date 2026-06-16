package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/elloloop/workspace/pkg/authz"
)

// modelResolver resolves a project's authorization model from the repository,
// caching the result. A project that does not exist, or that carries no model,
// resolves to authz.DefaultModel — so an unconfigured project behaves exactly
// like the built-in defaults. A configured project's namespaces are OVERLAID
// onto the defaults per namespace: the product surface (workspace, group,
// resource) is always present, and a project adds its own namespaces (course,
// lesson, …) or overrides a default one by redeclaring it. The cache is
// invalidated whenever a project is created or updated.
type modelResolver struct {
	repo  Repository
	mu    sync.RWMutex
	cache map[string]authz.Model
}

func newModelResolver(repo Repository) *modelResolver {
	return &modelResolver{repo: repo, cache: map[string]authz.Model{}}
}

func (r *modelResolver) ModelFor(ctx context.Context, projectID string) (authz.Model, error) {
	r.mu.RLock()
	m, ok := r.cache[projectID]
	r.mu.RUnlock()
	if ok {
		return m, nil
	}

	model := authz.DefaultModel()
	p, err := r.repo.GetProject(ctx, projectID)
	switch {
	case errors.Is(err, ErrNotFound):
		// Unconfigured project: fall back to the default model.
	case err != nil:
		return nil, err
	case len(p.Model) > 0:
		// Overlay the project's namespaces onto the defaults so the built-in
		// product surface (workspace/group/resource) survives a custom model;
		// a redeclared namespace overrides the default of the same name.
		for ns, rels := range p.Model {
			model[ns] = rels
		}
	}

	r.mu.Lock()
	r.cache[projectID] = model
	r.mu.Unlock()
	return model, nil
}

func (r *modelResolver) invalidate(projectID string) {
	r.mu.Lock()
	delete(r.cache, projectID)
	r.mu.Unlock()
}

// CreateProject registers a project and its (optional) authorization model.
// A nil model means the project uses the built-in default model. This is the
// configuration surface that lets two products (e.g. a kids platform and a
// professionals platform) run distinct models on one deployment.
func (s *Service) CreateProject(ctx context.Context, id, name string, model authz.Model) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	if err := validateModel(model); err != nil {
		return nil, err
	}
	now := s.now()
	p := &Project{
		ID:        id,
		Name:      name,
		Status:    ProjectActive,
		Model:     model,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, err
	}
	s.resolver.invalidate(id)
	return p, nil
}

// GetProject returns a project's configuration.
func (s *Service) GetProject(ctx context.Context, id string) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	return s.repo.GetProject(ctx, id)
}

// ListProjects returns every configured project.
func (s *Service) ListProjects(ctx context.Context) ([]*Project, error) {
	return s.repo.ListProjects(ctx)
}

// UpdateProject replaces a project's name, status, and model. A nil model
// resets the project to the default model.
func (s *Service) UpdateProject(ctx context.Context, id, name string, status ProjectStatus, model authz.Model) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	if status != ProjectActive && status != ProjectSuspended {
		return nil, fmt.Errorf("%w: status must be active or suspended", ErrInvalidArgument)
	}
	if err := validateModel(model); err != nil {
		return nil, err
	}
	p, err := s.repo.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Name = name
	p.Status = status
	p.Model = model
	p.UpdatedAt = s.now()
	if err := s.repo.UpdateProject(ctx, p); err != nil {
		return nil, err
	}
	s.resolver.invalidate(id)
	return p, nil
}

// EnsureDefaultProject idempotently seeds a project with the default model.
// It is called at boot for GATEWAY_DEFAULT_PROJECT_ID so the deployment's
// default shard is always resolvable, mirroring identity's bootstrap.
func (s *Service) EnsureDefaultProject(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if _, err := s.repo.GetProject(ctx, id); err == nil {
		return nil
	} else if !isNotFound(err) {
		return err
	}
	_, err := s.CreateProject(ctx, id, "Default", nil)
	if isAlreadyExists(err) {
		return nil // lost a race; the winner seeded it
	}
	return err
}

// validateModel round-trips the model through its JSON form to reject any
// structurally invalid rewrite before it is persisted.
func validateModel(m authz.Model) error {
	if len(m) == 0 {
		return nil
	}
	data, err := authz.MarshalModel(m)
	if err != nil {
		return fmt.Errorf("%w: model is not serializable: %w", ErrInvalidArgument, err)
	}
	if _, err := authz.ParseModel(data); err != nil {
		return fmt.Errorf("%w: invalid model: %w", ErrInvalidArgument, err)
	}
	return nil
}
