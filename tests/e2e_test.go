// Package tests holds black-box end-to-end tests that exercise the
// assembled workspace service over real HTTP via the generated Connect
// clients — the same surface a product backend (the workplace collaboration
// tool, the learning platform, the personal-assistant app) talks to.
//
// This is an internal service: the caller authenticates with a SERVICE
// credential (a shared token), and the acting user is passed as data in the
// request body — never inferred from a caller token. These tests drive the
// implementation against the in-memory driver with no external dependencies.
package tests

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/workspaceserver"
)

const svcToken = "service-credential-0123456789abcdef" //nolint:gosec // test-only service token

type harness struct {
	ws    workspacev1connect.WorkspaceServiceClient
	grp   workspacev1connect.GroupServiceClient
	authz workspacev1connect.AuthzServiceClient
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken},
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return &harness{
		ws:    workspacev1connect.NewWorkspaceServiceClient(c, hs.URL),
		grp:   workspacev1connect.NewGroupServiceClient(c, hs.URL),
		authz: workspacev1connect.NewAuthzServiceClient(c, hs.URL),
	}
}

// req wraps a message with the service credential the caller presents.
func req[T any](msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+svcToken)
	return r
}

func TestPersonalWorkspaceAutoProvisioned(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	resp, err := h.ws.ListWorkspaces(ctx, req(&workspacev1.ListWorkspacesRequest{ActingUserId: "alice"}))
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
	resp2, err := h.ws.ListWorkspaces(ctx, req(&workspacev1.ListWorkspacesRequest{ActingUserId: "alice"}))
	if err != nil {
		t.Fatalf("ListWorkspaces 2: %v", err)
	}
	if len(resp2.Msg.Workspaces) != 1 {
		t.Fatalf("personal workspace not idempotent: got %d", len(resp2.Msg.Workspaces))
	}
}

func TestMissingServiceCredentialRejected(t *testing.T) {
	h := newHarness(t)
	// No Authorization header → Unauthenticated.
	_, err := h.ws.ListWorkspaces(context.Background(),
		connect.NewRequest(&workspacev1.ListWorkspacesRequest{ActingUserId: "alice"}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated without credential, got %v", err)
	}

	// Wrong credential → Unauthenticated.
	bad := connect.NewRequest(&workspacev1.ListWorkspacesRequest{ActingUserId: "alice"})
	bad.Header().Set("Authorization", "Bearer not-the-token")
	_, err = h.ws.ListWorkspaces(context.Background(), bad)
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated with wrong credential, got %v", err)
	}
}

func TestMissingActingUserRejected(t *testing.T) {
	h := newHarness(t)
	// Authenticated service, but no acting_user_id → InvalidArgument.
	_, err := h.ws.ListWorkspaces(context.Background(), req(&workspacev1.ListWorkspacesRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want InvalidArgument without acting_user_id, got %v", err)
	}
}

func TestTeamWorkspaceMembershipAndAuthz(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Acme Inc",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	ws := created.Msg.Workspace
	if ws.Type != workspacev1.WorkspaceType_WORKSPACE_TYPE_TEAM {
		t.Fatalf("want TEAM, got %v", ws.Type)
	}

	// Owner adds bob as a member.
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := h.ws.ListMembers(ctx, req(&workspacev1.ListMembersRequest{ActingUserId: "alice", WorkspaceId: ws.Id}))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members.Msg.Members) != 2 {
		t.Fatalf("want 2 members, got %d", len(members.Msg.Members))
	}

	// Authz: owner ⊃ admin ⊃ member ⊃ guest. The subject is data, independent
	// of the acting/calling identity.
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
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
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
	_, err = h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "bob", WorkspaceId: ws.Id, UserId: "carol", Role: workspacev1.Role_ROLE_MEMBER,
	}))
	if err == nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied for member adding member, got %v", err)
	}
}

func TestPersonalWorkspaceIsClosed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	list, err := h.ws.ListWorkspaces(ctx, req(&workspacev1.ListWorkspacesRequest{ActingUserId: "alice"}))
	if err != nil {
		t.Fatalf("ListWorkspaces: %v", err)
	}
	personal := list.Msg.Workspaces[0]

	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: personal.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err == nil {
		t.Fatal("want error adding member to personal workspace")
	}
	if _, err := h.ws.DeleteWorkspace(ctx, req(&workspacev1.DeleteWorkspaceRequest{
		ActingUserId: "alice", WorkspaceId: personal.Id,
	})); err == nil {
		t.Fatal("want error deleting personal workspace")
	}
}

func TestInvitationFlow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Family"}))
	ws := created.Msg.Workspace

	inv, err := h.ws.CreateInvitation(ctx, req(&workspacev1.CreateInvitationRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, Email: "dad@example.com", Role: workspacev1.Role_ROLE_ADMIN,
	}))
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if inv.Msg.Invitation.Token == "" {
		t.Fatal("want non-empty invitation token")
	}

	// dad accepts (acting as user id "dad").
	acc, err := h.ws.AcceptInvitation(ctx, req(&workspacev1.AcceptInvitationRequest{
		ActingUserId: "dad", Token: inv.Msg.Invitation.Token,
	}))
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if acc.Msg.Membership.Role != workspacev1.Role_ROLE_ADMIN {
		t.Fatalf("want ADMIN after accept, got %v", acc.Msg.Membership.Role)
	}

	// dad is now an admin and can add members.
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "dad", WorkspaceId: ws.Id, UserId: "kid", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("admin AddMember: %v", err)
	}

	// Re-accepting a consumed token fails.
	if _, err := h.ws.AcceptInvitation(ctx, req(&workspacev1.AcceptInvitationRequest{
		ActingUserId: "dad", Token: inv.Msg.Invitation.Token,
	})); err == nil {
		t.Fatal("want error re-accepting consumed token")
	}
}

func TestGroupsGrantAccessViaUserset(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A standalone "family" group containing bob and carol.
	g, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{ActingUserId: "alice", DisplayName: "Family"}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for _, u := range []string{"bob", "carol"} {
		if _, err := h.grp.AddGroupMember(ctx, req(&workspacev1.AddGroupMemberRequest{
			ActingUserId: "alice", GroupId: g.Msg.Group.Id,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: u}},
		})); err != nil {
			t.Fatalf("AddGroupMember %s: %v", u, err)
		}
	}

	// Share a resource (a shared task / document) with the whole group:
	// resource:task-42#viewer@group:<id>#member.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
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

	for _, tc := range []struct {
		user string
		want bool
	}{{"bob", true}, {"carol", true}, {"dave", false}} {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
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

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Eng"}))
	ws := created.Msg.Workspace
	_, _ = h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	}))

	// A resource (Linear-style issue) declares its parent workspace:
	// resource:issue-7#parent@workspace:<ws>#member. viewer is computed from
	// the parent's members via tuple_to_userset.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
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

	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "issue-7", Relation: "viewer", SubjectUserId: "bob",
	}))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !got.Msg.Allowed {
		t.Fatal("bob should inherit viewer from parent workspace membership")
	}
}
