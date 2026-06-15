// Package tests holds black-box end-to-end tests that exercise the
// assembled workspace service over real HTTP via the generated Connect
// clients — the same surface an external consumer (the workplace
// collaboration tool, the learning platform, the personal-assistant app)
// talks to. These tests are written against the proto contract and drive
// the implementation: they must pass against the in-memory driver with no
// external dependencies.
package tests

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspaces/gen/go/workspace"
	"github.com/elloloop/workspaces/gen/go/workspace/workspaceconnect"
	"github.com/elloloop/workspaces/pkg/jwt"
	"github.com/elloloop/workspaces/workspaceserver"
)

const testSecret = "test-signing-secret-0123456789abcdef"

// harness builds a memory-backed server and returns Connect clients plus a
// helper to mint bearer tokens for a given user id.
type harness struct {
	ws    workspaceconnect.WorkspaceServiceClient
	grp   workspaceconnect.GroupServiceClient
	authz workspaceconnect.AuthzServiceClient
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger:   zaptest.NewLogger(t),
		Verifier: jwt.NewHS256Verifier(testSecret, "identity"),
		Config:   workspaceserver.Config{DefaultProjectID: "default"},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return &harness{
		ws:    workspaceconnect.NewWorkspaceServiceClient(c, hs.URL),
		grp:   workspaceconnect.NewGroupServiceClient(c, hs.URL),
		authz: workspaceconnect.NewAuthzServiceClient(c, hs.URL),
	}
}

func token(t *testing.T, userID string) string {
	t.Helper()
	tok, err := jwt.MintHS256(testSecret, "identity", userID, "default", time.Hour)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return tok
}

// auth wraps a request with the bearer token for userID.
func auth[T any](t *testing.T, userID string, msg *T) *connect.Request[T] {
	t.Helper()
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+token(t, userID))
	return r
}

func TestPersonalWorkspaceAutoProvisioned(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	resp, err := h.ws.ListWorkspaces(ctx, auth(t, "alice", &workspacev1.ListWorkspacesRequest{}))
	if err != nil {
		t.Fatalf("ListWorkspaces: %v", err)
	}
	if len(resp.Msg.Workspaces) != 1 {
		t.Fatalf("want 1 auto workspace, got %d", len(resp.Msg.Workspaces))
	}
	w := resp.Msg.Workspaces[0]
	if w.Type != workspacev1.WorkspaceType_WORKSPACE_TYPE_PERSONAL {
		t.Fatalf("want PERSONAL, got %v", w.Type)
	}
	if w.OwnerUserId != "alice" {
		t.Fatalf("want owner alice, got %q", w.OwnerUserId)
	}

	// Idempotent: a second call does not create a second personal workspace.
	resp2, err := h.ws.ListWorkspaces(ctx, auth(t, "alice", &workspacev1.ListWorkspacesRequest{}))
	if err != nil {
		t.Fatalf("ListWorkspaces 2: %v", err)
	}
	if len(resp2.Msg.Workspaces) != 1 {
		t.Fatalf("personal workspace not idempotent: got %d", len(resp2.Msg.Workspaces))
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	h := newHarness(t)
	_, err := h.ws.ListWorkspaces(context.Background(),
		connect.NewRequest(&workspacev1.ListWorkspacesRequest{}))
	if err == nil {
		t.Fatal("want error without token")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestTeamWorkspaceMembershipAndAuthz(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.ws.CreateWorkspace(ctx, auth(t, "alice", &workspacev1.CreateWorkspaceRequest{
		DisplayName: "Acme Inc",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	ws := created.Msg.Workspace
	if ws.Type != workspacev1.WorkspaceType_WORKSPACE_TYPE_TEAM {
		t.Fatalf("want TEAM, got %v", ws.Type)
	}

	// Owner adds bob as a member.
	if _, err := h.ws.AddMember(ctx, auth(t, "alice", &workspacev1.AddMemberRequest{
		WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := h.ws.ListMembers(ctx, auth(t, "alice", &workspacev1.ListMembersRequest{WorkspaceId: ws.Id}))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members.Msg.Members) != 2 {
		t.Fatalf("want 2 members, got %d", len(members.Msg.Members))
	}

	// Authz: owner ⊃ admin ⊃ member ⊃ guest.
	checks := []struct {
		rel  string
		user string
		want bool
	}{
		{"owner", "alice", true},
		{"admin", "alice", true},
		{"member", "alice", true},
		{"owner", "bob", false},
		{"admin", "bob", false},
		{"member", "bob", true},
		{"member", "carol", false},
	}
	for _, c := range checks {
		got, err := h.authz.Check(ctx, auth(t, "alice", &workspacev1.CheckRequest{
			Namespace: "workspace", ObjectId: ws.Id, Relation: c.rel, SubjectUserId: c.user,
		}))
		if err != nil {
			t.Fatalf("Check %s@%s: %v", c.rel, c.user, err)
		}
		if got.Msg.Allowed != c.want {
			t.Fatalf("Check %s@%s = %v, want %v", c.rel, c.user, got.Msg.Allowed, c.want)
		}
	}

	// bob (a plain member) cannot add members — needs admin.
	_, err = h.ws.AddMember(ctx, auth(t, "bob", &workspacev1.AddMemberRequest{
		WorkspaceId: ws.Id, UserId: "carol", Role: workspacev1.Role_ROLE_MEMBER,
	}))
	if err == nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied for member adding member, got %v", err)
	}
}

func TestPersonalWorkspaceIsClosed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	list, err := h.ws.ListWorkspaces(ctx, auth(t, "alice", &workspacev1.ListWorkspacesRequest{}))
	if err != nil {
		t.Fatalf("ListWorkspaces: %v", err)
	}
	personal := list.Msg.Workspaces[0]

	if _, err := h.ws.AddMember(ctx, auth(t, "alice", &workspacev1.AddMemberRequest{
		WorkspaceId: personal.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err == nil {
		t.Fatal("want error adding member to personal workspace")
	}
	if _, err := h.ws.DeleteWorkspace(ctx, auth(t, "alice", &workspacev1.DeleteWorkspaceRequest{
		WorkspaceId: personal.Id,
	})); err == nil {
		t.Fatal("want error deleting personal workspace")
	}
}

func TestInvitationFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, auth(t, "alice", &workspacev1.CreateWorkspaceRequest{DisplayName: "Family"}))
	ws := created.Msg.Workspace

	inv, err := h.ws.CreateInvitation(ctx, auth(t, "alice", &workspacev1.CreateInvitationRequest{
		WorkspaceId: ws.Id, Email: "dad@example.com", Role: workspacev1.Role_ROLE_ADMIN,
	}))
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.Msg.Invitation.Token == "" {
		t.Fatal("want non-empty invitation token")
	}

	// dad accepts (as user id "dad").
	acc, err := h.ws.AcceptInvitation(ctx, auth(t, "dad", &workspacev1.AcceptInvitationRequest{
		Token: inv.Msg.Invitation.Token,
	}))
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if acc.Msg.Membership.Role != workspacev1.Role_ROLE_ADMIN {
		t.Fatalf("want ADMIN after accept, got %v", acc.Msg.Membership.Role)
	}

	// dad is now an admin and can add members.
	if _, err := h.ws.AddMember(ctx, auth(t, "dad", &workspacev1.AddMemberRequest{
		WorkspaceId: ws.Id, UserId: "kid", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("admin AddMember: %v", err)
	}

	// Re-accepting a consumed token fails.
	if _, err := h.ws.AcceptInvitation(ctx, auth(t, "dad", &workspacev1.AcceptInvitationRequest{
		Token: inv.Msg.Invitation.Token,
	})); err == nil {
		t.Fatal("want error re-accepting consumed token")
	}
}

func TestGroupsGrantAccessViaUserset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A standalone "family" group containing bob and carol.
	g, err := h.grp.CreateGroup(ctx, auth(t, "alice", &workspacev1.CreateGroupRequest{DisplayName: "Family"}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for _, u := range []string{"bob", "carol"} {
		if _, err := h.grp.AddGroupMember(ctx, auth(t, "alice", &workspacev1.AddGroupMemberRequest{
			GroupId: g.Msg.Group.Id,
			Member:  &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: u}},
		})); err != nil {
			t.Fatalf("AddGroupMember %s: %v", u, err)
		}
	}

	// Share a resource (e.g. a shared task / document) with the whole group:
	// resource:task-42#viewer@group:<id>#member.
	if _, err := h.authz.WriteRelationTuples(ctx, auth(t, "alice", &workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "task-42", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "group", ObjectId: g.Msg.Group.Id, Relation: "member",
				}}},
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	// bob, a group member, can view the resource; dave cannot.
	for _, tc := range []struct {
		user string
		want bool
	}{{"bob", true}, {"carol", true}, {"dave", false}} {
		got, err := h.authz.Check(ctx, auth(t, "alice", &workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "task-42", Relation: "viewer", SubjectUserId: tc.user,
		}))
		if err != nil {
			t.Fatalf("Check viewer@%s: %v", tc.user, err)
		}
		if got.Msg.Allowed != tc.want {
			t.Fatalf("Check viewer@%s = %v, want %v", tc.user, got.Msg.Allowed, tc.want)
		}
	}
}

func TestResourceInheritsFromParentWorkspace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, auth(t, "alice", &workspacev1.CreateWorkspaceRequest{DisplayName: "Eng"}))
	ws := created.Msg.Workspace
	_, _ = h.ws.AddMember(ctx, auth(t, "alice", &workspacev1.AddMemberRequest{
		WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	}))

	// A resource (Linear-style issue) declares its parent workspace:
	// resource:issue-7#parent@workspace:<ws>. viewer is computed from the
	// parent's members via tuple_to_userset.
	if _, err := h.authz.WriteRelationTuples(ctx, auth(t, "alice", &workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "issue-7", Relation: "parent",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "workspace", ObjectId: ws.Id, Relation: "member",
				}}},
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	// bob inherits viewer on the issue through workspace membership.
	got, err := h.authz.Check(ctx, auth(t, "alice", &workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "issue-7", Relation: "viewer", SubjectUserId: "bob",
	}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !got.Msg.Allowed {
		t.Fatal("bob should inherit viewer from parent workspace membership")
	}
}
