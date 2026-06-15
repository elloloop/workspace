package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// AddMember grants userID the given role on a workspace. Requires the caller
// to be an admin (or owner). The role may not be `owner` — ownership is set
// at creation and transferred explicitly, not granted as a second owner.
func (s *Service) AddMember(ctx context.Context, p Principal, workspaceID, userID string, role Role) (*Membership, error) {
	if !role.Valid() || role == RoleOwner {
		return nil, fmt.Errorf("%w: role must be admin, member, or guest", ErrInvalidArgument)
	}
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	w, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin)
	if err != nil {
		return nil, err
	}
	if w.Type == TypePersonal {
		return nil, fmt.Errorf("%w: personal workspaces admit only their owner", ErrFailedPrecondition)
	}
	if _, err := s.repo.GetMembership(ctx, p.ProjectID, workspaceID, userID); err == nil {
		return nil, fmt.Errorf("%w: user is already a member", ErrAlreadyExists)
	} else if !isNotFound(err) {
		return nil, err
	}
	return s.putMember(ctx, p.ProjectID, workspaceID, userID, role)
}

// putMember writes the membership row and the backing role tuple.
func (s *Service) putMember(ctx context.Context, projectID, workspaceID, userID string, role Role) (*Membership, error) {
	now := s.now()
	m := &Membership{
		ProjectID:   projectID,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Role:        role,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.PutMembership(ctx, m); err != nil {
		return nil, err
	}
	if err := s.repo.WriteTuples(ctx, projectID,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(role), userID)}, nil); err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateMemberRole changes an existing member's role. Requires admin. The
// owner's role cannot be changed through this path.
func (s *Service) UpdateMemberRole(ctx context.Context, p Principal, workspaceID, userID string, role Role) (*Membership, error) {
	if !role.Valid() || role == RoleOwner {
		return nil, fmt.Errorf("%w: role must be admin, member, or guest", ErrInvalidArgument)
	}
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin); err != nil {
		return nil, err
	}
	m, err := s.repo.GetMembership(ctx, p.ProjectID, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	if m.Role == RoleOwner {
		return nil, fmt.Errorf("%w: the owner's role cannot be changed", ErrFailedPrecondition)
	}
	if m.Role == role {
		return m, nil
	}
	old := m.Role
	m.Role = role
	m.UpdatedAt = s.now()
	if err := s.repo.PutMembership(ctx, m); err != nil {
		return nil, err
	}
	if err := s.repo.WriteTuples(ctx, p.ProjectID,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(role), userID)},
		[]authz.Tuple{userTuple("workspace", workspaceID, string(old), userID)}); err != nil {
		return nil, err
	}
	return m, nil
}

// RemoveMember revokes a member. Requires admin. The owner cannot be removed.
func (s *Service) RemoveMember(ctx context.Context, p Principal, workspaceID, userID string) error {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin); err != nil {
		return err
	}
	m, err := s.repo.GetMembership(ctx, p.ProjectID, workspaceID, userID)
	if err != nil {
		return err
	}
	if m.Role == RoleOwner {
		return fmt.Errorf("%w: the owner cannot be removed", ErrFailedPrecondition)
	}
	if err := s.repo.DeleteMembership(ctx, p.ProjectID, workspaceID, userID); err != nil {
		return err
	}
	return s.repo.WriteTuples(ctx, p.ProjectID, nil,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(m.Role), userID)})
}

// ListMembers returns a workspace's members. Requires at least guest access.
func (s *Service) ListMembers(ctx context.Context, p Principal, workspaceID string) ([]*Membership, error) {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleGuest); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, p.ProjectID, workspaceID)
}
