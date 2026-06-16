package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestTransferOwnership: the owner transfers a team workspace to a member; the
// new owner gains `owner`, the old owner is demoted to `admin` (kept, not
// orphaned), and the workspace records the new owner.
func TestTransferOwnership(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Acme"}))
	ws := created.Msg.Workspace
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	resp, err := h.ws.TransferOwnership(ctx, req(&workspacev1.TransferOwnershipRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, NewOwnerUserId: "bob",
	}))
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if resp.Msg.Workspace.OwnerUserId != "bob" {
		t.Fatalf("owner_user_id = %q, want bob", resp.Msg.Workspace.OwnerUserId)
	}

	if !checkAllowed(ctx, t, h, "workspace", ws.Id, "owner", "bob") {
		t.Fatal("new owner bob should pass owner Check")
	}
	if checkAllowed(ctx, t, h, "workspace", ws.Id, "owner", "alice") {
		t.Fatal("former owner alice must NOT still be owner")
	}
	if !checkAllowed(ctx, t, h, "workspace", ws.Id, "admin", "alice") {
		t.Fatal("former owner alice should be demoted to admin, not orphaned")
	}
}

// TestTransferOwnershipGuards: only the owner may transfer, and personal
// workspaces cannot be transferred.
func TestTransferOwnershipGuards(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Acme"}))
	ws := created.Msg.Workspace
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "carol", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	// A non-owner cannot transfer.
	_, err := h.ws.TransferOwnership(ctx, req(&workspacev1.TransferOwnershipRequest{
		ActingUserId: "carol", WorkspaceId: ws.Id, NewOwnerUserId: "carol",
	}))
	if err == nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-owner transfer: want PermissionDenied, got %v", err)
	}

	// A personal workspace cannot be transferred.
	list, _ := h.ws.ListWorkspaces(ctx, req(&workspacev1.ListWorkspacesRequest{ActingUserId: "dave"}))
	var personal string
	for _, w := range list.Msg.Workspaces {
		if w.Type == workspacev1.WorkspaceType_WORKSPACE_TYPE_PERSONAL {
			personal = w.Id
		}
	}
	if personal == "" {
		t.Fatal("expected dave to have a personal workspace")
	}
	_, err = h.ws.TransferOwnership(ctx, req(&workspacev1.TransferOwnershipRequest{
		ActingUserId: "dave", WorkspaceId: personal, NewOwnerUserId: "erin",
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("personal transfer: want FailedPrecondition, got %v", err)
	}
}

// TestTransferOwnershipSuspendedProject: a suspended project rejects the
// management write, failing closed.
func TestTransferOwnershipSuspendedProject(t *testing.T) {
	h := newAdminHarness(t)
	ctx := context.Background()
	const proj = "p-transfer"

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{Id: proj, Name: "T"})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Acme", ProjectId: proj,
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	ws := created.Msg.Workspace
	if _, err := h.admin.UpdateProject(ctx, reqAdmin(&workspacev1.UpdateProjectRequest{
		Id: proj, Status: workspacev1.ProjectStatus_PROJECT_STATUS_SUSPENDED,
	})); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	_, err = h.ws.TransferOwnership(ctx, req(&workspacev1.TransferOwnershipRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, NewOwnerUserId: "bob", ProjectId: proj,
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("suspended project transfer: want FailedPrecondition, got %v", err)
	}
}
