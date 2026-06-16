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
	if _, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID); err == nil {
		return nil, fmt.Errorf("%w: user is already a member", ErrAlreadyExists)
	} else if !isNotFound(err) {
		return nil, err
	}
	return s.putMember(ctx, p, workspaceID, userID, role)
}

// putMember writes the membership row and the backing role tuple.
func (s *Service) putMember(ctx context.Context, p Principal, workspaceID, userID string, role Role) (*Membership, error) {
	now := s.now()
	m := &Membership{
		ProjectID:   p.ProjectID,
		TenantID:    p.TenantID,
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
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID,
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
	m, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	if m.Role == RoleOwner {
		return nil, fmt.Errorf("%w: the owner's role cannot be changed", ErrFailedPrecondition)
	}
	if m.Status == StatusSuspended {
		// A suspended member holds no role tuple (access was revoked by tuple
		// absence). Writing the new role tuple here would silently re-grant live
		// access while the membership still reads suspended — reinstate first.
		return nil, fmt.Errorf("%w: member is suspended; reinstate before changing their role", ErrFailedPrecondition)
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
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID,
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
	m, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID)
	if err != nil {
		return err
	}
	if m.Role == RoleOwner {
		return fmt.Errorf("%w: the owner cannot be removed", ErrFailedPrecondition)
	}
	if err := s.repo.DeleteMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID); err != nil {
		return err
	}
	return s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, nil,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(m.Role), userID)})
}

// ListMembers returns a workspace's members. Requires at least guest access.
func (s *Service) ListMembers(ctx context.Context, p Principal, workspaceID string) ([]*Membership, error) {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleGuest); err != nil {
		return nil, err
	}
	return s.repo.ListMembers(ctx, p.ProjectID, p.TenantID, workspaceID)
}

// SuspendMember pauses a member's access WITHOUT deleting their membership: it
// deletes the backing role tuple (so every Check denies immediately and they
// drop out of active workspace listings) and marks the membership suspended.
// Requires admin; the owner cannot be suspended. Denial is by tuple absence —
// no status read on the hot path. ReinstateMember reverses it.
func (s *Service) SuspendMember(ctx context.Context, p Principal, workspaceID, userID string) (*Membership, error) {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin); err != nil {
		return nil, err
	}
	m, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	if m.Role == RoleOwner {
		return nil, fmt.Errorf("%w: the owner cannot be suspended", ErrFailedPrecondition)
	}
	if m.Status == StatusSuspended {
		return m, nil
	}
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, nil,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(m.Role), userID)}); err != nil {
		return nil, err
	}
	m.Status = StatusSuspended
	m.UpdatedAt = s.now()
	if err := s.repo.PutMembership(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

// ReinstateMember restores a suspended member: it re-writes the role tuple
// from the stored role and marks the membership active. Requires admin.
func (s *Service) ReinstateMember(ctx context.Context, p Principal, workspaceID, userID string) (*Membership, error) {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin); err != nil {
		return nil, err
	}
	m, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, userID)
	if err != nil {
		return nil, err
	}
	if m.Status != StatusSuspended {
		return m, nil
	}
	// Persist the membership row BEFORE writing the access-granting tuple: these
	// are two non-atomic repo calls, so order them fail-closed — a crash between
	// them leaves the row active but no tuple (Check denies) rather than granting
	// access against a still-suspended row. (A single transactional membership+
	// tuple write is the tracked follow-up; SuspendMember is already fail-closed
	// because it removes the tuple first.)
	m.Status = StatusActive
	m.UpdatedAt = s.now()
	if err := s.repo.PutMembership(ctx, m); err != nil {
		return nil, err
	}
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(m.Role), userID)}, nil); err != nil {
		return nil, err
	}
	return m, nil
}
