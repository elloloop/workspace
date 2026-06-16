package service

import (
	"context"
	"fmt"
	"time"
)

// InvitationTTL is how long an invite token stays valid.
const InvitationTTL = 7 * 24 * time.Hour

// CreateInvitation issues a token-based invite to a workspace. Requires
// admin. The returned Invitation carries the one-time plaintext token (only
// here); the store keeps only its hash.
func (s *Service) CreateInvitation(ctx context.Context, p Principal, workspaceID, email string, role Role) (*Invitation, string, error) {
	if !role.Valid() || role == RoleOwner {
		return nil, "", fmt.Errorf("%w: role must be admin, member, or guest", ErrInvalidArgument)
	}
	email = trimName(email)
	if email == "" {
		return nil, "", fmt.Errorf("%w: email is required", ErrInvalidArgument)
	}
	w, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin)
	if err != nil {
		return nil, "", err
	}
	if w.Type == TypePersonal {
		return nil, "", fmt.Errorf("%w: personal workspaces cannot be shared", ErrFailedPrecondition)
	}
	now := s.now()
	token := randHex(24)
	inv := &Invitation{
		ID:          s.newID(),
		ProjectID:   p.ProjectID,
		TenantID:    p.TenantID,
		WorkspaceID: workspaceID,
		Email:       email,
		Role:        role,
		Status:      InvitePending,
		InvitedBy:   p.UserID,
		TokenHash:   hashToken(token),
		CreatedAt:   now,
		ExpiresAt:   now.Add(InvitationTTL),
	}
	if err := s.repo.CreateInvitation(ctx, inv); err != nil {
		return nil, "", err
	}
	return inv, token, nil
}

// AcceptInvitation consumes a pending invite for the calling user, adding
// them to the workspace with the invited role.
func (s *Service) AcceptInvitation(ctx context.Context, p Principal, token string) (*Membership, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidArgument)
	}
	inv, err := s.repo.GetInvitationByTokenHash(ctx, p.ProjectID, p.TenantID, hashToken(token))
	if err != nil {
		return nil, err
	}
	if inv.Status != InvitePending {
		return nil, fmt.Errorf("%w: invitation is %s", ErrFailedPrecondition, inv.Status)
	}
	if s.now().After(inv.ExpiresAt) {
		inv.Status = InviteExpired
		_ = s.repo.UpdateInvitation(ctx, inv)
		return nil, fmt.Errorf("%w: invitation has expired", ErrFailedPrecondition)
	}

	m, err := s.repo.GetMembership(ctx, p.ProjectID, p.TenantID, inv.WorkspaceID, p.UserID)
	if err == nil {
		// Already a member: consume the invite, keep the existing role.
		inv.Status = InviteAccepted
		if err := s.repo.UpdateInvitation(ctx, inv); err != nil {
			return nil, err
		}
		return m, nil
	} else if !isNotFound(err) {
		return nil, err
	}

	m, err = s.putMember(ctx, p, inv.WorkspaceID, p.UserID, inv.Role)
	if err != nil {
		return nil, err
	}
	inv.Status = InviteAccepted
	if err := s.repo.UpdateInvitation(ctx, inv); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Service) ListInvitations(ctx context.Context, p Principal, workspaceID string) ([]*Invitation, error) {
	if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleAdmin); err != nil {
		return nil, err
	}
	return s.repo.ListInvitations(ctx, p.ProjectID, p.TenantID, workspaceID)
}

func (s *Service) RevokeInvitation(ctx context.Context, p Principal, invitationID string) error {
	inv, err := s.repo.GetInvitation(ctx, p.ProjectID, p.TenantID, invitationID)
	if err != nil {
		return err
	}
	if _, err := s.requireWorkspace(ctx, p, inv.WorkspaceID, RoleAdmin); err != nil {
		return err
	}
	if inv.Status == InvitePending {
		inv.Status = InviteRevoked
		return s.repo.UpdateInvitation(ctx, inv)
	}
	return nil
}
