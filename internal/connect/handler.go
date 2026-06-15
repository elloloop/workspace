// Package connect adapts the transport-agnostic service.Service to the
// generated Connect-RPC handler interfaces: it pulls the authenticated
// principal from context, translates proto ⇄ domain types, and maps service
// sentinel errors to wire status codes.
package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspaces/gen/go/workspace"
	"github.com/elloloop/workspaces/internal/middleware"
	"github.com/elloloop/workspaces/internal/service"
)

// Handler implements WorkspaceServiceHandler, GroupServiceHandler, and
// AuthzServiceHandler over a single Service.
type Handler struct {
	svc *service.Service
}

// NewHandler builds the Connect handler for svc.
func NewHandler(svc *service.Service) *Handler { return &Handler{svc: svc} }

// principal extracts the authenticated caller; absence is Unauthenticated.
func principal(ctx context.Context) (service.Principal, error) {
	p, ok := middleware.PrincipalFrom(ctx)
	if !ok {
		return service.Principal{}, connect.NewError(connect.CodeUnauthenticated, errors.New("missing or invalid credentials"))
	}
	return p, nil
}

// errToConnect maps service sentinel errors to Connect status codes.
func errToConnect(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, service.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, service.ErrAlreadyExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, service.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, service.ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, service.ErrFailedPrecondition):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// ── proto ⇄ domain converters ─────────────────────────────────────────────

func roleToProto(r service.Role) workspacev1.Role {
	switch r {
	case service.RoleOwner:
		return workspacev1.Role_ROLE_OWNER
	case service.RoleAdmin:
		return workspacev1.Role_ROLE_ADMIN
	case service.RoleMember:
		return workspacev1.Role_ROLE_MEMBER
	case service.RoleGuest:
		return workspacev1.Role_ROLE_GUEST
	default:
		return workspacev1.Role_ROLE_UNSPECIFIED
	}
}

func roleFromProto(r workspacev1.Role) service.Role {
	switch r {
	case workspacev1.Role_ROLE_OWNER:
		return service.RoleOwner
	case workspacev1.Role_ROLE_ADMIN:
		return service.RoleAdmin
	case workspacev1.Role_ROLE_MEMBER:
		return service.RoleMember
	case workspacev1.Role_ROLE_GUEST:
		return service.RoleGuest
	default:
		return ""
	}
}

func wsTypeToProto(t service.WorkspaceType) workspacev1.WorkspaceType {
	if t == service.TypePersonal {
		return workspacev1.WorkspaceType_WORKSPACE_TYPE_PERSONAL
	}
	return workspacev1.WorkspaceType_WORKSPACE_TYPE_TEAM
}

func membershipStatusToProto(s service.MembershipStatus) workspacev1.MembershipStatus {
	switch s {
	case service.StatusActive:
		return workspacev1.MembershipStatus_MEMBERSHIP_STATUS_ACTIVE
	case service.StatusInvited:
		return workspacev1.MembershipStatus_MEMBERSHIP_STATUS_INVITED
	case service.StatusSuspended:
		return workspacev1.MembershipStatus_MEMBERSHIP_STATUS_SUSPENDED
	default:
		return workspacev1.MembershipStatus_MEMBERSHIP_STATUS_UNSPECIFIED
	}
}

func inviteStatusToProto(s service.InvitationStatus) workspacev1.InvitationStatus {
	switch s {
	case service.InvitePending:
		return workspacev1.InvitationStatus_INVITATION_STATUS_PENDING
	case service.InviteAccepted:
		return workspacev1.InvitationStatus_INVITATION_STATUS_ACCEPTED
	case service.InviteRevoked:
		return workspacev1.InvitationStatus_INVITATION_STATUS_REVOKED
	case service.InviteExpired:
		return workspacev1.InvitationStatus_INVITATION_STATUS_EXPIRED
	default:
		return workspacev1.InvitationStatus_INVITATION_STATUS_UNSPECIFIED
	}
}

func workspaceToProto(w *service.Workspace) *workspacev1.Workspace {
	return &workspacev1.Workspace{
		Id:          w.ID,
		ProjectId:   w.ProjectID,
		Slug:        w.Slug,
		DisplayName: w.DisplayName,
		Type:        wsTypeToProto(w.Type),
		OwnerUserId: w.OwnerUserID,
		CreatedAt:   timestamppb.New(w.CreatedAt),
		UpdatedAt:   timestamppb.New(w.UpdatedAt),
	}
}

func membershipToProto(m *service.Membership) *workspacev1.Membership {
	return &workspacev1.Membership{
		WorkspaceId: m.WorkspaceID,
		UserId:      m.UserID,
		Role:        roleToProto(m.Role),
		Status:      membershipStatusToProto(m.Status),
		CreatedAt:   timestamppb.New(m.CreatedAt),
		UpdatedAt:   timestamppb.New(m.UpdatedAt),
	}
}

func invitationToProto(inv *service.Invitation, token string) *workspacev1.Invitation {
	return &workspacev1.Invitation{
		Id:              inv.ID,
		WorkspaceId:     inv.WorkspaceID,
		Email:           inv.Email,
		Role:            roleToProto(inv.Role),
		Status:          inviteStatusToProto(inv.Status),
		InvitedByUserId: inv.InvitedBy,
		CreatedAt:       timestamppb.New(inv.CreatedAt),
		ExpiresAt:       timestamppb.New(inv.ExpiresAt),
		Token:           token,
	}
}

func groupToProto(g *service.Group) *workspacev1.Group {
	return &workspacev1.Group{
		Id:              g.ID,
		ProjectId:       g.ProjectID,
		WorkspaceId:     g.WorkspaceID,
		Slug:            g.Slug,
		DisplayName:     g.DisplayName,
		CreatedByUserId: g.CreatedBy,
		CreatedAt:       timestamppb.New(g.CreatedAt),
		UpdatedAt:       timestamppb.New(g.UpdatedAt),
	}
}
