package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// TransferOwnership hands a TEAM workspace's ownership from the acting owner to
// newOwnerID. Only the current owner may do it; personal workspaces and a
// suspended project are rejected. The new owner is granted the `owner` role
// (added as a member if not already one) and the former owner is demoted to
// `admin` so they keep access rather than being orphaned.
//
// Each membership+tuple change commits atomically (PutMembershipAndTuples), so
// a crash can never strand a membership row without its role tuple. The new
// owner is promoted before the former owner is demoted, so there is never a
// window with no owner — at worst a brief moment where both hold `owner`.
func (s *Service) TransferOwnership(ctx context.Context, p Principal, workspaceID, newOwnerID string) (*Workspace, error) {
	if newOwnerID == "" {
		return nil, fmt.Errorf("%w: new_owner_user_id is required", ErrInvalidArgument)
	}
	// Only the current owner may transfer.
	w, err := s.requireWorkspace(ctx, p, workspaceID, RoleOwner)
	if err != nil {
		return nil, err
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return nil, err
	}
	if w.Type == TypePersonal {
		return nil, fmt.Errorf("%w: personal workspaces cannot be transferred", ErrFailedPrecondition)
	}
	oldOwnerID := w.OwnerUserID
	if newOwnerID == oldOwnerID {
		return w, nil // no-op
	}
	now := s.now()

	// 1. Promote the new owner: write their `owner` tuple, removing any prior
	//    non-owner role tuple, and upsert their membership row to owner/active.
	existing, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, newOwnerID)
	var deletes []authz.Tuple
	switch {
	case err == nil:
		if existing.Role != RoleOwner {
			deletes = append(deletes, userTuple("workspace", workspaceID, string(existing.Role), newOwnerID))
		}
	case isNotFound(err):
		existing = nil
	default:
		return nil, err
	}
	newOwner := &Membership{
		ProjectID:   p.ProjectID,
		TenantID:    p.TenantID,
		WorkspaceID: workspaceID,
		UserID:      newOwnerID,
		Role:        RoleOwner,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		newOwner.CreatedAt = existing.CreatedAt
	}
	if err := s.repo.PutMembershipAndTuples(ctx, newOwner,
		[]authz.Tuple{userTuple("workspace", workspaceID, string(RoleOwner), newOwnerID)}, deletes); err != nil {
		return nil, err
	}

	// 2. Record the new owner on the workspace.
	w.OwnerUserID = newOwnerID
	w.UpdatedAt = now
	if err := s.repo.UpdateWorkspace(ctx, w); err != nil {
		return nil, err
	}

	// 3. Demote the former owner to admin: atomically swap their `owner` tuple
	//    for `admin` together with the membership-row update.
	adminInsert := []authz.Tuple{userTuple("workspace", workspaceID, string(RoleAdmin), oldOwnerID)}
	ownerDelete := []authz.Tuple{userTuple("workspace", workspaceID, string(RoleOwner), oldOwnerID)}
	switch old, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, workspaceID, oldOwnerID); {
	case err == nil:
		old.Role = RoleAdmin
		old.UpdatedAt = now
		if err := s.repo.PutMembershipAndTuples(ctx, old, adminInsert, ownerDelete); err != nil {
			return nil, err
		}
	case isNotFound(err):
		// No membership row for the former owner (edge case): just swap tuples.
		if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, adminInsert, ownerDelete); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return w, nil
}
