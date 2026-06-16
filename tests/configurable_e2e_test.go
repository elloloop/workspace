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

const adminSecret = "test-admin-secret-0123456789abcdef-32+" //nolint:gosec // test-only admin secret (>= minAdminSecretLen)

type adminHarness struct {
	ws    workspacev1connect.WorkspaceServiceClient
	authz workspacev1connect.AuthzServiceClient
	admin workspacev1connect.AdminServiceClient
}

func newAdminHarness(t *testing.T) *adminHarness {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken},
			AdminAPISecret:    adminSecret,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return &adminHarness{
		ws:    workspacev1connect.NewWorkspaceServiceClient(c, hs.URL),
		authz: workspacev1connect.NewAuthzServiceClient(c, hs.URL),
		admin: workspacev1connect.NewAdminServiceClient(c, hs.URL),
	}
}

// reqAdmin presents both the service credential and the admin secret.
func reqAdmin[T any](msg *T) *connect.Request[T] {
	r := req(msg)
	r.Header().Set("X-Admin-Secret", adminSecret)
	return r
}

func checkAllowed(ctx context.Context, t *testing.T, h *harness, ns, obj, rel, user string) bool {
	t.Helper()
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: ns, ObjectId: obj, Relation: rel, SubjectUserId: user,
	}))
	if err != nil {
		t.Fatalf("Check %s:%s#%s@%s: %v", ns, obj, rel, user, err)
	}
	return got.Msg.Allowed
}

// TestSuspendReinstateRevokesAccess is the P0 regression: a suspended member
// must fail every Check (access revoked by tuple absence) and drop out of
// active workspace listings, and reinstating must restore both.
func TestSuspendReinstateRevokesAccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Acme"}))
	ws := created.Msg.Workspace
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if !checkAllowed(ctx, t, h, "workspace", ws.Id, "member", "bob") {
		t.Fatal("bob should be a member before suspension")
	}

	// Suspend bob.
	susp, err := h.ws.SuspendMember(ctx, req(&workspacev1.SuspendMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob",
	}))
	if err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}
	if susp.Msg.Membership.Status != workspacev1.MembershipStatus_MEMBERSHIP_STATUS_SUSPENDED {
		t.Fatalf("want SUSPENDED, got %v", susp.Msg.Membership.Status)
	}
	if checkAllowed(ctx, t, h, "workspace", ws.Id, "member", "bob") {
		t.Fatal("SUSPENDED member must FAIL Check — this is the P0 fix")
	}
	// bob's active workspace listing no longer includes the team.
	list, _ := h.ws.ListWorkspaces(ctx, req(&workspacev1.ListWorkspacesRequest{ActingUserId: "bob"}))
	for _, w := range list.Msg.Workspaces {
		if w.Id == ws.Id {
			t.Fatal("suspended member should not see the workspace in active listings")
		}
	}

	// Reinstate restores access.
	if _, err := h.ws.ReinstateMember(ctx, req(&workspacev1.ReinstateMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob",
	})); err != nil {
		t.Fatalf("ReinstateMember: %v", err)
	}
	if !checkAllowed(ctx, t, h, "workspace", ws.Id, "member", "bob") {
		t.Fatal("reinstated member should pass Check again")
	}

	// The owner cannot be suspended.
	if _, err := h.ws.SuspendMember(ctx, req(&workspacev1.SuspendMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "alice",
	})); err == nil || connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition suspending owner, got %v", err)
	}
}

// TestUpdateMemberRoleOnSuspendedFailsClosed: changing a suspended member's
// role must NOT silently re-grant access — it is refused until reinstatement.
func TestUpdateMemberRoleOnSuspendedFailsClosed(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{ActingUserId: "alice", DisplayName: "Acme"}))
	ws := created.Msg.Workspace
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := h.ws.SuspendMember(ctx, req(&workspacev1.SuspendMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob",
	})); err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}

	// Promoting the suspended member must fail closed, not re-grant access.
	_, err := h.ws.UpdateMemberRole(ctx, req(&workspacev1.UpdateMemberRoleRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_ADMIN,
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want FailedPrecondition updating suspended member, got %v", err)
	}
	if checkAllowed(ctx, t, h, "workspace", ws.Id, "member", "bob") {
		t.Fatal("suspended member must still be denied after a role-change attempt")
	}
	if checkAllowed(ctx, t, h, "workspace", ws.Id, "admin", "bob") {
		t.Fatal("the refused promotion must not have granted admin")
	}
}

// TestWildcardPublicGrant: a wildcard tuple grants the relation to any user
// (link-sharing / published content).
func TestWildcardPublicGrant(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "published-course", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Wildcard{Wildcard: true}},
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples wildcard: %v", err)
	}
	for _, u := range []string{"anyone", "nobody-in-particular"} {
		if !checkAllowed(ctx, t, h, "resource", "published-course", "viewer", u) {
			t.Fatalf("wildcard should admit %q", u)
		}
	}
}

// TestListObjects: the reverse index returns every object a user can access.
func TestListObjects(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	writes := []*workspacev1.TupleUpdate{
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{
			Namespace: "course", ObjectId: "c1", Relation: "viewer",
			Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "amy"}},
		}},
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{
			Namespace: "course", ObjectId: "c2", Relation: "viewer",
			Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Wildcard{Wildcard: true}},
		}},
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{
			Namespace: "course", ObjectId: "c3", Relation: "viewer",
			Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "ben"}},
		}},
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{Updates: writes})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	got, err := h.authz.ListObjects(ctx, req(&workspacev1.ListObjectsRequest{
		Namespace: "course", Relation: "viewer", SubjectUserId: "amy",
	}))
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	want := map[string]bool{"c1": true, "c2": true} // direct + public, not c3
	if len(got.Msg.ObjectIds) != 2 {
		t.Fatalf("ListObjects = %v, want [c1 c2]", got.Msg.ObjectIds)
	}
	for _, id := range got.Msg.ObjectIds {
		if !want[id] {
			t.Errorf("unexpected object %q", id)
		}
	}
}

// TestDeprovisionUser wipes every grant a departing user holds, across
// namespaces.
func TestDeprovisionUser(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	writes := []*workspacev1.TupleUpdate{}
	for _, x := range []struct{ ns, obj, rel string }{
		{"workspace", "w1", "owner"}, {"group", "g1", "member"}, {"resource", "doc1", "viewer"},
	} {
		writes = append(writes, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: x.ns, ObjectId: x.obj, Relation: x.rel,
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "bob"}},
			},
		})
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{Updates: writes})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	// bob also holds a grant in a DIFFERENT tenant of the same project.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		TenantId: "t2",
		Updates: []*workspacev1.TupleUpdate{{
			Op:    workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{Namespace: "resource", ObjectId: "doc2", Relation: "viewer", Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "bob"}}},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples tenant t2: %v", err)
	}

	// A single deprovision erases across ALL tenants of the project (tenant_id
	// on the request is ignored for erase).
	resp, err := h.authz.DeprovisionUser(ctx, req(&workspacev1.DeprovisionUserRequest{UserId: "bob"}))
	if err != nil {
		t.Fatalf("DeprovisionUser: %v", err)
	}
	if resp.Msg.DeletedCount != 4 {
		t.Fatalf("deleted = %d, want 4 (3 in default tenant + 1 in t2)", resp.Msg.DeletedCount)
	}
	if checkAllowed(ctx, t, h, "resource", "doc1", "viewer", "bob") {
		t.Fatal("bob's default-tenant grants should be gone after deprovisioning")
	}
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "resource", ObjectId: "doc2", Relation: "viewer", SubjectUserId: "bob", TenantId: "t2",
	}))
	if err != nil {
		t.Fatalf("Check t2: %v", err)
	}
	if got.Msg.Allowed {
		t.Fatal("bob's sibling-tenant grant must also be erased (cross-tenant leak)")
	}
}

// TestTenantIsolationOverAPI: data written under one tenant is invisible under
// another tenant of the same project.
func TestTenantIsolationOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "TenantA Co", TenantId: "tenant-a",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	ws := created.Msg.Workspace
	if ws.TenantId != "tenant-a" {
		t.Fatalf("want tenant-a, got %q", ws.TenantId)
	}

	// In its own tenant, alice owns it.
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: ws.Id, Relation: "owner", SubjectUserId: "alice", TenantId: "tenant-a",
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("owner check in tenant-a = %v, %v", got.Msg.Allowed, err)
	}
	// In another tenant, the tuple does not exist.
	got, err = h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: ws.Id, Relation: "owner", SubjectUserId: "alice", TenantId: "tenant-b",
	}))
	if err != nil {
		t.Fatalf("cross-tenant check err: %v", err)
	}
	if got.Msg.Allowed {
		t.Fatal("workspace ownership leaked across tenants")
	}
	// The workspace row is invisible in the other tenant.
	if _, err := h.ws.GetWorkspace(ctx, req(&workspacev1.GetWorkspaceRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, TenantId: "tenant-b",
	})); err == nil || connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want NotFound across tenant, got %v", err)
	}
}

// TestAdminPerProjectModel: a project configured with a custom model evaluates
// Check by that model, while the default project keeps the built-in model.
func TestAdminPerProjectModel(t *testing.T) {
	h := newAdminHarness(t)
	ctx := context.Background()

	// course.can_view = enrolled AND paid — a model the default project lacks.
	const model = `{"course":{` +
		`"enrolled":{"this":true},` +
		`"paid":{"this":true},` +
		`"can_view":{"intersection":[{"computed":"enrolled"},{"computed":"paid"}]}}}`

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "pro", Name: "Professionals", ModelJson: model,
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// amy is enrolled+paid; ben only enrolled — in project "pro".
	writes := []*workspacev1.TupleUpdate{
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{ProjectId: "pro", Namespace: "course", ObjectId: "c1", Relation: "enrolled", Subject: subjUser("amy")}},
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{ProjectId: "pro", Namespace: "course", ObjectId: "c1", Relation: "paid", Subject: subjUser("amy")}},
		{Op: workspacev1.TupleUpdate_OP_INSERT, Tuple: &workspacev1.RelationTuple{ProjectId: "pro", Namespace: "course", ObjectId: "c1", Relation: "enrolled", Subject: subjUser("ben")}},
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{ProjectId: "pro", Updates: writes})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	mustCheck := func(user string, want bool) {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			ProjectId: "pro", Namespace: "course", ObjectId: "c1", Relation: "can_view", SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s: %v", user, err)
		}
		if got.Msg.Allowed != want {
			t.Fatalf("can_view@%s = %v, want %v", user, got.Msg.Allowed, want)
		}
	}
	mustCheck("amy", true)  // enrolled AND paid
	mustCheck("ben", false) // enrolled only — intersection denies

	// The custom model is OVERLAID on the defaults: the built-in workspace
	// role hierarchy still works in project "pro" (owner ⊃ member).
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		ProjectId: "pro", Updates: []*workspacev1.TupleUpdate{{
			Op:    workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{ProjectId: "pro", Namespace: "workspace", ObjectId: "w1", Relation: "owner", Subject: subjUser("amy")},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples workspace: %v", err)
	}
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		ProjectId: "pro", Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "amy",
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("default workspace hierarchy lost under custom model: member@amy = %v, %v", got.Msg.Allowed, err)
	}
}

// adminClientNoSecret builds an AdminService client against a server that has
// NO admin secret configured, so the admin RPCs are disabled.
func adminClientNoSecret(t *testing.T) workspacev1connect.AdminServiceClient {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{DefaultProjectID: "default", ServiceAuthTokens: []string{svcToken}},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return workspacev1connect.NewAdminServiceClient(hs.Client(), hs.URL)
}

// TestAdminGating: the admin API is disabled without a secret, and rejects a
// wrong/missing secret when one is configured.
func TestAdminGating(t *testing.T) {
	ctx := context.Background()

	// No admin secret configured → Unimplemented.
	_, err := adminClientNoSecret(t).ListProjects(ctx, req(&workspacev1.ListProjectsRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("want Unimplemented with no admin secret, got %v", err)
	}

	// Secret configured but request omits it → Unauthenticated.
	h := newAdminHarness(t)
	_, err = h.admin.ListProjects(ctx, req(&workspacev1.ListProjectsRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated without admin secret, got %v", err)
	}
	// With the secret → ok.
	if _, err := h.admin.ListProjects(ctx, reqAdmin(&workspacev1.ListProjectsRequest{})); err != nil {
		t.Fatalf("ListProjects with secret: %v", err)
	}
}

func subjUser(id string) *workspacev1.Subject {
	return &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: id}}
}
