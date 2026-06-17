// Package connect adapts the transport-agnostic service.Service to the
// generated Connect-RPC handler interfaces: it reads the acting user and
// project from the request body (the calling service is already
// authenticated by the ServiceAuth middleware), translates proto ⇄ domain
// types, and maps service sentinel errors to wire status codes.
package connect

import (
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/internal/service"
)

// Handler implements WorkspaceServiceHandler, GroupServiceHandler, and
// AuthzServiceHandler over a single Service. The calling service is already
// authenticated by the ServiceAuth middleware; these handlers read the
// acting user and project from the request body (Zanzibar-style, user as
// data) rather than from a caller token.
type Handler struct {
	svc              *service.Service
	defaultProjectID string
	// defaultTenantID is applied when a request omits tenant_id (the project's
	// default tenant), symmetric with defaultProjectID.
	defaultTenantID string
	// adminSecret gates the AdminService (project configuration). Empty
	// disables the admin RPCs entirely, mirroring identity.
	adminSecret string
	// maxBatchCheckItems caps a single BatchCheck request.
	maxBatchCheckItems int
	// adminLimiter throttles the AdminService per caller; nil disables it.
	adminLimiter *rateLimiter
	// tenantLimiter throttles authz data-plane RPCs per (project, tenant); nil
	// disables it (the default).
	tenantLimiter *rateLimiter
	// metrics records authorization decision counters/histograms exposed at
	// /metrics; nil-safe, so it never affects a decision.
	metrics *metrics
}

// NewHandler builds the Connect handler for svc. defaultProjectID/defaultTenantID
// are applied when a request omits project_id/tenant_id (single-shard
// deployments). adminSecret gates the AdminService; empty disables it.
// maxBatchCheckItems caps BatchCheck request size; non-positive uses the default.
// adminRateLimitPerMinute throttles the admin surface per caller; non-positive
// disables the limiter. tenantRateLimitPerMinute throttles authz data-plane
// RPCs per (project, tenant); non-positive disables it.
func NewHandler(svc *service.Service, defaultProjectID, defaultTenantID, adminSecret string, maxBatchCheckItems, adminRateLimitPerMinute, tenantRateLimitPerMinute int) *Handler {
	if defaultProjectID == "" {
		defaultProjectID = "default"
	}
	if maxBatchCheckItems <= 0 {
		maxBatchCheckItems = config.DefaultMaxBatchCheckItems
	}
	return &Handler{
		svc:                svc,
		defaultProjectID:   defaultProjectID,
		defaultTenantID:    defaultTenantID,
		adminSecret:        adminSecret,
		maxBatchCheckItems: maxBatchCheckItems,
		adminLimiter:       newRateLimiter(adminRateLimitPerMinute, nil),
		tenantLimiter:      newRateLimiter(tenantRateLimitPerMinute, nil),
		metrics:            defaultMetrics(),
	}
}

// requireTenantRate throttles authz data-plane RPCs per resolved (project,
// tenant). A nil tenantLimiter (disabled) always allows. Over-limit returns
// ResourceExhausted. The key uses the resolved scope so empty project_id/
// tenant_id map to the deployment defaults, consistent with the handler.
func (h *Handler) requireTenantRate(projectID, tenantID string) error {
	if h.tenantLimiter.allow(h.projectOr(projectID) + "\x00" + h.tenantOr(tenantID)) {
		return nil
	}
	return connect.NewError(connect.CodeResourceExhausted, errors.New("tenant rate limit exceeded"))
}

// acting builds the Principal a management RPC acts as. acting_user_id is
// required (the action must be authorized against a known user); project_id
// falls back to the deployment default when empty; tenant_id is the
// data-isolation shard (empty = default tenant).
func (h *Handler) acting(actingUserID, projectID, tenantID string) (service.Principal, error) {
	if actingUserID == "" {
		return service.Principal{}, connect.NewError(connect.CodeInvalidArgument, errors.New("acting_user_id is required"))
	}
	return service.Principal{UserID: actingUserID, ProjectID: h.projectOr(projectID), TenantID: h.tenantOr(tenantID)}, nil
}

// scope is the Principal for an authz RPC: only the project/tenant matter; the
// subject is a request argument, not the caller.
func (h *Handler) scope(projectID, tenantID string) service.Principal {
	return service.Principal{ProjectID: h.projectOr(projectID), TenantID: h.tenantOr(tenantID)}
}

func (h *Handler) projectOr(projectID string) string {
	if projectID == "" {
		return h.defaultProjectID
	}
	return projectID
}

func (h *Handler) tenantOr(tenantID string) string {
	if tenantID == "" {
		return h.defaultTenantID
	}
	return tenantID
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
	case errors.Is(err, service.ErrResourceExhausted):
		return connect.NewError(connect.CodeResourceExhausted, err)
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
		TenantId:    w.TenantID,
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
		TenantId:    m.TenantID,
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
		TenantId:        inv.TenantID,
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
		TenantId:        g.TenantID,
		WorkspaceId:     g.WorkspaceID,
		Slug:            g.Slug,
		DisplayName:     g.DisplayName,
		CreatedByUserId: g.CreatedBy,
		CreatedAt:       timestamppb.New(g.CreatedAt),
		UpdatedAt:       timestamppb.New(g.UpdatedAt),
	}
}
