package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestWorkspaceAdminManagesGroup covers requireGroupManager's workspace-admin
// branch: a workspace-scoped group is manageable by a workspace ADMIN who did
// NOT create the group (not just its creator), while an unrelated user is denied.
func TestWorkspaceAdminManagesGroup(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// alice owns a workspace and promotes bob to ADMIN of it.
	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Acme",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	wsID := created.Msg.Workspace.Id
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: wsID, UserId: "bob", Role: workspacev1.Role_ROLE_ADMIN,
	})); err != nil {
		t.Fatalf("AddMember admin: %v", err)
	}

	// alice creates a group SCOPED to that workspace.
	grp, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{
		ActingUserId: "alice", DisplayName: "Eng", WorkspaceId: wsID,
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	gID := grp.Msg.Group.Id

	addAs := func(actor, member string) error {
		_, err := h.grp.AddGroupMember(ctx, req(&workspacev1.AddGroupMemberRequest{
			ActingUserId: actor, GroupId: gID,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: member}},
		}))
		return err
	}

	// bob is a workspace ADMIN but NOT the group's creator — he may manage it.
	if err := addAs("bob", "u1"); err != nil {
		t.Fatalf("workspace admin must manage a workspace-scoped group, got: %v", err)
	}
	// carol is neither creator nor workspace admin — denied.
	if err := addAs("carol", "u2"); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-manager must be denied; got %v", err)
	}
}
