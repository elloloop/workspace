package connect

import (
	"context"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

func (h *Handler) CreateWorkspace(ctx context.Context, req *connect.Request[workspacev1.CreateWorkspaceRequest]) (*connect.Response[workspacev1.CreateWorkspaceResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	w, err := h.svc.CreateWorkspace(ctx, p, req.Msg.DisplayName, req.Msg.Slug)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.CreateWorkspaceResponse{Workspace: workspaceToProto(w)}), nil
}

func (h *Handler) GetWorkspace(ctx context.Context, req *connect.Request[workspacev1.GetWorkspaceRequest]) (*connect.Response[workspacev1.GetWorkspaceResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	w, err := h.svc.GetWorkspace(ctx, p, req.Msg.WorkspaceId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.GetWorkspaceResponse{Workspace: workspaceToProto(w)}), nil
}

func (h *Handler) ListWorkspaces(ctx context.Context, req *connect.Request[workspacev1.ListWorkspacesRequest]) (*connect.Response[workspacev1.ListWorkspacesResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	ws, err := h.svc.ListWorkspaces(ctx, p)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.Workspace, 0, len(ws))
	for _, w := range ws {
		out = append(out, workspaceToProto(w))
	}
	return connect.NewResponse(&workspacev1.ListWorkspacesResponse{Workspaces: out}), nil
}

func (h *Handler) UpdateWorkspace(ctx context.Context, req *connect.Request[workspacev1.UpdateWorkspaceRequest]) (*connect.Response[workspacev1.UpdateWorkspaceResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	w, err := h.svc.UpdateWorkspace(ctx, p, req.Msg.WorkspaceId, req.Msg.DisplayName)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.UpdateWorkspaceResponse{Workspace: workspaceToProto(w)}), nil
}

func (h *Handler) TransferOwnership(ctx context.Context, req *connect.Request[workspacev1.TransferOwnershipRequest]) (*connect.Response[workspacev1.TransferOwnershipResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	w, err := h.svc.TransferOwnership(ctx, p, req.Msg.WorkspaceId, req.Msg.NewOwnerUserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.TransferOwnershipResponse{Workspace: workspaceToProto(w)}), nil
}

func (h *Handler) DeleteWorkspace(ctx context.Context, req *connect.Request[workspacev1.DeleteWorkspaceRequest]) (*connect.Response[workspacev1.DeleteWorkspaceResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteWorkspace(ctx, p, req.Msg.WorkspaceId); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.DeleteWorkspaceResponse{}), nil
}

func (h *Handler) AddMember(ctx context.Context, req *connect.Request[workspacev1.AddMemberRequest]) (*connect.Response[workspacev1.AddMemberResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.AddMember(ctx, p, req.Msg.WorkspaceId, req.Msg.UserId, roleFromProto(req.Msg.Role))
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.AddMemberResponse{Membership: membershipToProto(m)}), nil
}

func (h *Handler) UpdateMemberRole(ctx context.Context, req *connect.Request[workspacev1.UpdateMemberRoleRequest]) (*connect.Response[workspacev1.UpdateMemberRoleResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.UpdateMemberRole(ctx, p, req.Msg.WorkspaceId, req.Msg.UserId, roleFromProto(req.Msg.Role))
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.UpdateMemberRoleResponse{Membership: membershipToProto(m)}), nil
}

func (h *Handler) RemoveMember(ctx context.Context, req *connect.Request[workspacev1.RemoveMemberRequest]) (*connect.Response[workspacev1.RemoveMemberResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RemoveMember(ctx, p, req.Msg.WorkspaceId, req.Msg.UserId); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.RemoveMemberResponse{}), nil
}

func (h *Handler) SuspendMember(ctx context.Context, req *connect.Request[workspacev1.SuspendMemberRequest]) (*connect.Response[workspacev1.SuspendMemberResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.SuspendMember(ctx, p, req.Msg.WorkspaceId, req.Msg.UserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.SuspendMemberResponse{Membership: membershipToProto(m)}), nil
}

func (h *Handler) ReinstateMember(ctx context.Context, req *connect.Request[workspacev1.ReinstateMemberRequest]) (*connect.Response[workspacev1.ReinstateMemberResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.ReinstateMember(ctx, p, req.Msg.WorkspaceId, req.Msg.UserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.ReinstateMemberResponse{Membership: membershipToProto(m)}), nil
}

func (h *Handler) ListMembers(ctx context.Context, req *connect.Request[workspacev1.ListMembersRequest]) (*connect.Response[workspacev1.ListMembersResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	members, err := h.svc.ListMembers(ctx, p, req.Msg.WorkspaceId)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.Membership, 0, len(members))
	for _, m := range members {
		out = append(out, membershipToProto(m))
	}
	return connect.NewResponse(&workspacev1.ListMembersResponse{Members: out}), nil
}

func (h *Handler) CreateInvitation(ctx context.Context, req *connect.Request[workspacev1.CreateInvitationRequest]) (*connect.Response[workspacev1.CreateInvitationResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	inv, token, err := h.svc.CreateInvitation(ctx, p, req.Msg.WorkspaceId, req.Msg.Email, roleFromProto(req.Msg.Role))
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.CreateInvitationResponse{Invitation: invitationToProto(inv, token)}), nil
}

func (h *Handler) AcceptInvitation(ctx context.Context, req *connect.Request[workspacev1.AcceptInvitationRequest]) (*connect.Response[workspacev1.AcceptInvitationResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := h.svc.AcceptInvitation(ctx, p, req.Msg.Token)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.AcceptInvitationResponse{Membership: membershipToProto(m)}), nil
}

func (h *Handler) ListInvitations(ctx context.Context, req *connect.Request[workspacev1.ListInvitationsRequest]) (*connect.Response[workspacev1.ListInvitationsResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	invs, err := h.svc.ListInvitations(ctx, p, req.Msg.WorkspaceId)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.Invitation, 0, len(invs))
	for _, inv := range invs {
		out = append(out, invitationToProto(inv, "")) // never echo the token
	}
	return connect.NewResponse(&workspacev1.ListInvitationsResponse{Invitations: out}), nil
}

func (h *Handler) RevokeInvitation(ctx context.Context, req *connect.Request[workspacev1.RevokeInvitationRequest]) (*connect.Response[workspacev1.RevokeInvitationResponse], error) {
	p, err := h.acting(req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RevokeInvitation(ctx, p, req.Msg.InvitationId); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.RevokeInvitationResponse{}), nil
}
