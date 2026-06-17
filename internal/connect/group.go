package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/service"
)

func groupMemberFromProto(m *workspacev1.GroupMember) (service.GroupMember, error) {
	if m == nil {
		return service.GroupMember{}, connect.NewError(connect.CodeInvalidArgument, errors.New("member is required"))
	}
	switch k := m.Member.(type) {
	case *workspacev1.GroupMember_UserId:
		return service.GroupMember{UserID: k.UserId}, nil
	case *workspacev1.GroupMember_GroupId:
		return service.GroupMember{GroupID: k.GroupId}, nil
	default:
		return service.GroupMember{}, connect.NewError(connect.CodeInvalidArgument, errors.New("member must set user_id or group_id"))
	}
}

func groupMemberToProto(m service.GroupMember) *workspacev1.GroupMember {
	if m.GroupID != "" {
		return &workspacev1.GroupMember{Member: &workspacev1.GroupMember_GroupId{GroupId: m.GroupID}}
	}
	return &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: m.UserID}}
}

func (h *Handler) CreateGroup(ctx context.Context, req *connect.Request[workspacev1.CreateGroupRequest]) (*connect.Response[workspacev1.CreateGroupResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.CreateGroup(ctx, p, req.Msg.DisplayName, req.Msg.Slug, req.Msg.WorkspaceId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.CreateGroupResponse{Group: groupToProto(g)}), nil
}

func (h *Handler) GetGroup(ctx context.Context, req *connect.Request[workspacev1.GetGroupRequest]) (*connect.Response[workspacev1.GetGroupResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	g, err := h.svc.GetGroup(ctx, p, req.Msg.GroupId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.GetGroupResponse{Group: groupToProto(g)}), nil
}

func (h *Handler) ListGroups(ctx context.Context, req *connect.Request[workspacev1.ListGroupsRequest]) (*connect.Response[workspacev1.ListGroupsResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	groups, err := h.svc.ListGroups(ctx, p, req.Msg.WorkspaceId)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupToProto(g))
	}
	return connect.NewResponse(&workspacev1.ListGroupsResponse{Groups: out}), nil
}

func (h *Handler) DeleteGroup(ctx context.Context, req *connect.Request[workspacev1.DeleteGroupRequest]) (*connect.Response[workspacev1.DeleteGroupResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.DeleteGroup(ctx, p, req.Msg.GroupId); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.DeleteGroupResponse{}), nil
}

func (h *Handler) AddGroupMember(ctx context.Context, req *connect.Request[workspacev1.AddGroupMemberRequest]) (*connect.Response[workspacev1.AddGroupMemberResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := groupMemberFromProto(req.Msg.Member)
	if err != nil {
		return nil, err
	}
	if err := h.svc.AddGroupMember(ctx, p, req.Msg.GroupId, m); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.AddGroupMemberResponse{}), nil
}

func (h *Handler) RemoveGroupMember(ctx context.Context, req *connect.Request[workspacev1.RemoveGroupMemberRequest]) (*connect.Response[workspacev1.RemoveGroupMemberResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	m, err := groupMemberFromProto(req.Msg.Member)
	if err != nil {
		return nil, err
	}
	if err := h.svc.RemoveGroupMember(ctx, p, req.Msg.GroupId, m); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.RemoveGroupMemberResponse{}), nil
}

func (h *Handler) ListGroupMembers(ctx context.Context, req *connect.Request[workspacev1.ListGroupMembersRequest]) (*connect.Response[workspacev1.ListGroupMembersResponse], error) {
	p, err := h.acting(ctx, req.Msg.ActingUserId, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	members, err := h.svc.ListGroupMembers(ctx, p, req.Msg.GroupId)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.GroupMember, 0, len(members))
	for _, m := range members {
		out = append(out, groupMemberToProto(m))
	}
	return connect.NewResponse(&workspacev1.ListGroupMembersResponse{Members: out}), nil
}
