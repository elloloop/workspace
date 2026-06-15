package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestWorkspaceLifecycle exercises get/update/delete and the member-management
// RPCs end to end, including their error paths.
func TestWorkspaceLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Acme"}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	id := created.Msg.Workspace.Id

	got, err := h.ws.GetWorkspace(ctx, req(&workspacev1.GetWorkspaceRequest{ActingUserId: "alice", WorkspaceId: id}))
	if err != nil || got.Msg.Workspace.DisplayName != "Acme" {
		t.Fatalf("GetWorkspace: %v / %v", err, got)
	}

	upd, err := h.ws.UpdateWorkspace(ctx, req(&workspacev1.UpdateWorkspaceRequest{ActingUserId: "alice", WorkspaceId: id, DisplayName: "Acme Corp"}))
	if err != nil || upd.Msg.Workspace.DisplayName != "Acme Corp" {
		t.Fatalf("UpdateWorkspace: %v / %v", err, upd)
	}

	// Add bob, promote to admin, then demote and remove.
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{ActingUserId: "alice", WorkspaceId: id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	promoted, err := h.ws.UpdateMemberRole(ctx, req(&workspacev1.UpdateMemberRoleRequest{ActingUserId: "alice", WorkspaceId: id, UserId: "bob", Role: workspacev1.Role_ROLE_ADMIN}))
	if err != nil || promoted.Msg.Membership.Role != workspacev1.Role_ROLE_ADMIN {
		t.Fatalf("UpdateMemberRole: %v / %v", err, promoted)
	}
	if _, err := h.ws.RemoveMember(ctx, req(&workspacev1.RemoveMemberRequest{ActingUserId: "alice", WorkspaceId: id, UserId: "bob"})); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	// Error paths.
	if _, err := h.ws.GetWorkspace(ctx, req(&workspacev1.GetWorkspaceRequest{ActingUserId: "alice", WorkspaceId: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound for missing workspace, got %v", err)
	}
	if _, err := h.ws.UpdateWorkspace(ctx, req(&workspacev1.UpdateWorkspaceRequest{ActingUserId: "alice", WorkspaceId: id, DisplayName: ""})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for empty name, got %v", err)
	}
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{ActingUserId: "alice", WorkspaceId: id, UserId: "x", Role: workspacev1.Role_ROLE_OWNER})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument granting owner, got %v", err)
	}

	// Owner deletes the team workspace.
	if _, err := h.ws.DeleteWorkspace(ctx, req(&workspacev1.DeleteWorkspaceRequest{ActingUserId: "alice", WorkspaceId: id})); err != nil {
		t.Fatalf("DeleteWorkspace: %v", err)
	}
	if _, err := h.ws.GetWorkspace(ctx, req(&workspacev1.GetWorkspaceRequest{ActingUserId: "alice", WorkspaceId: id})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}

// TestGroupLifecycle exercises the full GroupService surface, including nested
// groups and Get/List/Delete.
func TestGroupLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	eng, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{ActingUserId: "alice", DisplayName: "Engineering"}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	backend, _ := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{ActingUserId: "alice", DisplayName: "Backend"}))
	gid := eng.Msg.Group.Id

	// Nest backend into engineering and add a direct user.
	if _, err := h.grp.AddGroupMember(ctx, req(&workspacev1.AddGroupMemberRequest{
		ActingUserId: "alice", GroupId: gid,
		Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_GroupId{GroupId: backend.Msg.Group.Id}},
	})); err != nil {
		t.Fatalf("AddGroupMember (nested): %v", err)
	}
	if _, err := h.grp.AddGroupMember(ctx, req(&workspacev1.AddGroupMemberRequest{
		ActingUserId: "alice", GroupId: gid,
		Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: "bob"}},
	})); err != nil {
		t.Fatalf("AddGroupMember (user): %v", err)
	}

	got, err := h.grp.GetGroup(ctx, req(&workspacev1.GetGroupRequest{ActingUserId: "alice", GroupId: gid}))
	if err != nil || got.Msg.Group.DisplayName != "Engineering" {
		t.Fatalf("GetGroup: %v / %v", err, got)
	}
	list, err := h.grp.ListGroups(ctx, req(&workspacev1.ListGroupsRequest{ActingUserId: "alice"}))
	if err != nil || len(list.Msg.Groups) != 2 {
		t.Fatalf("ListGroups: %v / %d", err, len(list.Msg.Groups))
	}
	members, err := h.grp.ListGroupMembers(ctx, req(&workspacev1.ListGroupMembersRequest{ActingUserId: "alice", GroupId: gid}))
	if err != nil || len(members.Msg.Members) != 2 {
		t.Fatalf("ListGroupMembers: %v / %d", err, len(members.Msg.Members))
	}

	if _, err := h.grp.RemoveGroupMember(ctx, req(&workspacev1.RemoveGroupMemberRequest{
		ActingUserId: "alice", GroupId: gid,
		Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: "bob"}},
	})); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	if _, err := h.grp.DeleteGroup(ctx, req(&workspacev1.DeleteGroupRequest{ActingUserId: "alice", GroupId: gid})); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
}

// TestAuthzReadAndExpand covers ReadRelationTuples and Expand, plus invitation
// revocation and the unauthenticated/invalid-tuple error paths.
func TestAuthzReadAndExpand(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	ws, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Eng"}))
	id := ws.Msg.Workspace.Id

	// Read the owner tuple written at creation.
	read, err := h.authz.ReadRelationTuples(ctx, req(&workspacev1.ReadRelationTuplesRequest{Namespace: "workspace", ObjectId: id, Relation: "owner"}))
	if err != nil || len(read.Msg.Tuples) != 1 || read.Msg.Tuples[0].GetSubject().GetUserId() != "alice" {
		t.Fatalf("ReadRelationTuples: %v / %v", err, read.Msg.Tuples)
	}

	// Expand the member userset → a tree.
	exp, err := h.authz.Expand(ctx, req(&workspacev1.ExpandRequest{Namespace: "workspace", ObjectId: id, Relation: "member"}))
	if err != nil || exp.Msg.Tree == nil {
		t.Fatalf("Expand: %v / %v", err, exp.Msg)
	}

	// Invalid tuple write → InvalidArgument.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{Namespace: "", ObjectId: "x", Relation: "viewer", Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "u"}}}}},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument for empty namespace, got %v", err)
	}

	// Invitation create + revoke + list.
	inv, _ := h.ws.CreateInvitation(ctx, req(&workspacev1.CreateInvitationRequest{ActingUserId: "alice", WorkspaceId: id, Email: "x@e.com", Role: workspacev1.Role_ROLE_MEMBER}))
	invs, err := h.ws.ListInvitations(ctx, req(&workspacev1.ListInvitationsRequest{ActingUserId: "alice", WorkspaceId: id}))
	if err != nil || len(invs.Msg.Invitations) != 1 || invs.Msg.Invitations[0].Token != "" {
		t.Fatalf("ListInvitations: %v / %v", err, invs.Msg.Invitations)
	}
	if _, err := h.ws.RevokeInvitation(ctx, req(&workspacev1.RevokeInvitationRequest{ActingUserId: "alice", InvitationId: inv.Msg.Invitation.Id})); err != nil {
		t.Fatalf("RevokeInvitation: %v", err)
	}
	// Accepting a revoked invite fails.
	if _, err := h.ws.AcceptInvitation(ctx, req(&workspacev1.AcceptInvitationRequest{ActingUserId: "x", Token: inv.Msg.Invitation.Token})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition accepting revoked invite, got %v", err)
	}
}
