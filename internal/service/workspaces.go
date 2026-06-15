package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspaces/pkg/authz"
)

// EnsurePersonalWorkspace returns the caller's personal workspace, creating
// it on first call. It is idempotent: concurrent first calls converge on a
// single personal workspace (the repo enforces one-personal-per-user).
func (s *Service) EnsurePersonalWorkspace(ctx context.Context, p Principal) (*Workspace, error) {
	if w, err := s.repo.PersonalWorkspace(ctx, p.ProjectID, p.UserID); err == nil {
		return w, nil
	} else if !isNotFound(err) {
		return nil, err
	}
	now := s.now()
	w := &Workspace{
		ID:          s.newID(),
		ProjectID:   p.ProjectID,
		Slug:        "personal",
		DisplayName: "Personal",
		Type:        TypePersonal,
		OwnerUserID: p.UserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.createWorkspaceWithOwner(ctx, p, w); err != nil {
		// Lost a race: another call created it first. Return the winner.
		if isAlreadyExists(err) {
			return s.repo.PersonalWorkspace(ctx, p.ProjectID, p.UserID)
		}
		return nil, err
	}
	return w, nil
}

// CreateWorkspace creates a TEAM workspace owned by the caller.
func (s *Service) CreateWorkspace(ctx context.Context, p Principal, displayName, slug string) (*Workspace, error) {
	displayName = trimName(displayName)
	if displayName == "" {
		return nil, fmt.Errorf("%w: display_name is required", ErrInvalidArgument)
	}
	if slug == "" {
		slug = slugify(displayName)
	} else {
		slug = slugify(slug)
	}
	now := s.now()
	w := &Workspace{
		ID:          s.newID(),
		ProjectID:   p.ProjectID,
		Slug:        slug,
		DisplayName: displayName,
		Type:        TypeTeam,
		OwnerUserID: p.UserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.createWorkspaceWithOwner(ctx, p, w); err != nil {
		return nil, err
	}
	return w, nil
}

// createWorkspaceWithOwner persists the workspace, the owner membership, and
// the `workspace:<id>#owner@user` tuple that backs every later authz check.
func (s *Service) createWorkspaceWithOwner(ctx context.Context, p Principal, w *Workspace) error {
	if err := s.repo.CreateWorkspace(ctx, w); err != nil {
		return err
	}
	m := &Membership{
		ProjectID:   w.ProjectID,
		WorkspaceID: w.ID,
		UserID:      w.OwnerUserID,
		Role:        RoleOwner,
		Status:      StatusActive,
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
	if err := s.repo.PutMembership(ctx, m); err != nil {
		return err
	}
	return s.repo.WriteTuples(ctx, w.ProjectID,
		[]authz.Tuple{userTuple("workspace", w.ID, string(RoleOwner), w.OwnerUserID)}, nil)
}

func (s *Service) GetWorkspace(ctx context.Context, p Principal, id string) (*Workspace, error) {
	return s.requireWorkspace(ctx, p, id, RoleGuest)
}

func (s *Service) ListWorkspaces(ctx context.Context, p Principal) ([]*Workspace, error) {
	if _, err := s.EnsurePersonalWorkspace(ctx, p); err != nil {
		return nil, err
	}
	return s.repo.WorkspacesForUser(ctx, p.ProjectID, p.UserID)
}

func (s *Service) UpdateWorkspace(ctx context.Context, p Principal, id, displayName string) (*Workspace, error) {
	w, err := s.requireWorkspace(ctx, p, id, RoleAdmin)
	if err != nil {
		return nil, err
	}
	displayName = trimName(displayName)
	if displayName == "" {
		return nil, fmt.Errorf("%w: display_name is required", ErrInvalidArgument)
	}
	w.DisplayName = displayName
	w.UpdatedAt = s.now()
	if err := s.repo.UpdateWorkspace(ctx, w); err != nil {
		return nil, err
	}
	return w, nil
}

// DeleteWorkspace removes a TEAM workspace, its memberships, and its tuples.
// Personal workspaces are undeletable.
func (s *Service) DeleteWorkspace(ctx context.Context, p Principal, id string) error {
	w, err := s.requireWorkspace(ctx, p, id, RoleOwner)
	if err != nil {
		return err
	}
	if w.Type == TypePersonal {
		return fmt.Errorf("%w: personal workspaces cannot be deleted", ErrFailedPrecondition)
	}
	return s.repo.DeleteWorkspace(ctx, p.ProjectID, id)
}
