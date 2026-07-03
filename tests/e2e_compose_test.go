//go:build composee2e

// Black-box FULL-STACK end-to-end tests. Unlike the in-process harness in
// e2e_test.go (which drives the assembled handler against the in-memory driver
// via httptest), these run realistic authz scenarios against the ACTUAL built
// service container on a real Postgres, reached over the network. That closes
// the gap the in-process suite can't: boot-time auto-migration, real pgx
// persistence and JSON/structpb round-trips, and service-token auth as
// deployed.
//
// Gated by the composee2e build tag and skipped unless WORKSPACES_E2E_BASE_URL
// points at a running stack. `make e2e-compose` builds + boots
// docker-compose.e2e.yml, sets the URL, and runs these.
package tests

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
)

// composeBaseURL returns the running stack's base URL, skipping the test when
// WORKSPACES_E2E_BASE_URL is unset (so `go test -tags=composee2e ./...` is
// dev-safe without a stack), and waiting for /healthz so the first RPC does not
// race container boot + auto-migration. `make e2e-compose` always sets the URL.
func composeBaseURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("WORKSPACES_E2E_BASE_URL")
	if base == "" {
		t.Skip("set WORKSPACES_E2E_BASE_URL (or run `make e2e-compose`) to run the full-stack compose e2e")
	}
	waitReady(t, base)
	return base
}

// newComposeHarness builds the same client set as newHarness, but pointed at
// the real service URL that `make e2e-compose` boots. The compose stack is
// configured with svcToken as its GATEWAY_SERVICE_AUTH_TOKENS, so the shared
// req() helper (which presents that token) authenticates unchanged.
func newComposeHarness(t *testing.T) *harness {
	t.Helper()
	base := composeBaseURL(t)
	c := http.DefaultClient
	return &harness{
		ws:    workspacev1connect.NewWorkspaceServiceClient(c, base),
		grp:   workspacev1connect.NewGroupServiceClient(c, base),
		authz: workspacev1connect.NewAuthzServiceClient(c, base),
	}
}

// waitReady polls /healthz until the service answers 200 or the deadline
// passes, so the first RPC does not race container boot + auto-migration.
func waitReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz") //nolint:noctx // test-only readiness poll
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service at %s did not become ready within the deadline", base)
}

// TestComposeTeamWorkspaceAuthz drives a realistic multi-actor authz scenario
// end-to-end against the real container + Postgres: create a team workspace,
// add a member, and verify the role lattice (owner ⊃ admin ⊃ member ⊃ guest)
// resolves correctly through the network, the full handler chain, and real
// persistence — and that a plain member is denied an admin-only mutation.
//
// It mirrors the in-process TestTeamWorkspaceMembershipAndAuthz so a divergence
// between the memory driver and the deployed Postgres stack surfaces here.
func TestComposeTeamWorkspaceAuthz(t *testing.T) {
	h := newComposeHarness(t)
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

	// Owner adds bob as a plain member.
	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id, UserId: "bob", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	members, err := h.ws.ListMembers(ctx, req(&workspacev1.ListMembersRequest{
		ActingUserId: "alice", WorkspaceId: ws.Id,
	}))
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members.Msg.Members) != 2 {
		t.Fatalf("want 2 members (alice, bob), got %d", len(members.Msg.Members))
	}

	// The role lattice must resolve identically to the in-process suite —
	// through real HTTP, the handler chain, and Postgres.
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

	// bob (a plain member) cannot add members — that needs admin. This asserts
	// the deny path is enforced by the deployed service, not just in memory.
	_, err = h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "bob", WorkspaceId: ws.Id, UserId: "carol", Role: workspacev1.Role_ROLE_MEMBER,
	}))
	if err == nil || connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied for member adding member, got %v", err)
	}
}

// TestComposeInvitationFlow drives the invitation lifecycle against the real
// stack: create a workspace, invite an admin, accept the token (as the invited
// user), confirm the accepted role, exercise the granted admin authority, and
// prove a consumed token cannot be replayed — all through real persistence.
func TestComposeInvitationFlow(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	created, err := h.ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Family",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
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

// TestComposeGroupsGrantAccessViaUserset shares a resource with a whole group
// via a userset tuple (resource#viewer@group#member) and verifies membership
// resolution through the group indirection against real Postgres.
func TestComposeGroupsGrantAccessViaUserset(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

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

// TestComposeConditionGatedCheck exercises attribute-aware grants end to end:
// a consent-gated and an age-gated tuple are evaluated against the request
// context through real pgx condition round-trips, and an unknown condition is
// rejected at write time.
func TestComposeConditionGatedCheck(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "c1", Relation: "viewer",
				Subject:       subjUser("kid"),
				ConditionName: "consent_granted",
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples consent: %v", err)
	}

	consentAllows := func(consent any) bool {
		var cc *structpb.Struct
		if consent != nil {
			cc = mustStruct(t, map[string]any{"consent": consent})
		}
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "course", ObjectId: "c1", Relation: "viewer", SubjectUserId: "kid", Context: cc,
		}))
		if err != nil {
			t.Fatalf("Check consent: %v", err)
		}
		return got.Msg.Allowed
	}
	if consentAllows(nil) {
		t.Fatal("no context: consent-gated grant must deny")
	}
	if consentAllows(false) {
		t.Fatal("consent=false: must deny")
	}
	if !consentAllows(true) {
		t.Fatal("consent=true: must allow")
	}

	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "rated", Relation: "viewer",
				Subject:         subjUser("kid"),
				ConditionName:   "age_at_least",
				ConditionParams: mustStruct(t, map[string]any{"min_age": float64(13)}),
			},
		}},
	})); err != nil {
		t.Fatalf("WriteRelationTuples age: %v", err)
	}
	ageAllows := func(age float64) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "course", ObjectId: "rated", Relation: "viewer", SubjectUserId: "kid",
			Context: mustStruct(t, map[string]any{"age": age}),
		}))
		if err != nil {
			t.Fatalf("Check age: %v", err)
		}
		return got.Msg.Allowed
	}
	if ageAllows(9) {
		t.Fatal("age 9 below band: must deny")
	}
	if !ageAllows(15) {
		t.Fatal("age 15 in band: must allow")
	}

	// An unknown condition is rejected at write time.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "x", Relation: "viewer",
				Subject:       subjUser("kid"),
				ConditionName: "no_such_condition",
			},
		}},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown condition must be rejected at write, got %v", err)
	}
}

// TestComposeSeatEnforcement drives seat capacity end to end against real
// Postgres advisory-locked assignment: a sku capped at N admits N and fails
// closed on the next, the backing seat#holder tuple gates Check, revocation
// frees a slot, and a second tenant's cap is independent.
func TestComposeSeatEnforcement(t *testing.T) {
	base := composeBaseURL(t)
	seat := workspacev1connect.NewSeatServiceClient(http.DefaultClient, base)
	authz := workspacev1connect.NewAuthzServiceClient(http.DefaultClient, base)
	ctx := context.Background()

	if _, err := seat.SetSeatLimit(ctx, req(&workspacev1.SetSeatLimitRequest{Sku: "pro", Limit: proto.Int32(2)})); err != nil {
		t.Fatalf("SetSeatLimit: %v", err)
	}
	assign := func(user string) error {
		_, err := seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: user}))
		return err
	}
	if err := assign("u1"); err != nil {
		t.Fatalf("assign u1: %v", err)
	}
	if err := assign("u2"); err != nil {
		t.Fatalf("assign u2: %v", err)
	}
	if err := assign("u3"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("assign u3 over cap: want ResourceExhausted, got %v", err)
	}

	holds := func(user string) bool {
		got, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "seat", ObjectId: "pro", Relation: "holder", SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s: %v", user, err)
		}
		return got.Msg.Allowed
	}
	if !holds("u1") || holds("u3") {
		t.Fatalf("seat tuple gate: u1=%v (want true) u3=%v (want false)", holds("u1"), holds("u3"))
	}

	usage, err := seat.GetSeatUsage(ctx, req(&workspacev1.GetSeatUsageRequest{Sku: "pro"}))
	if err != nil || usage.Msg.Used != 2 || usage.Msg.Limit != 2 || !usage.Msg.Limited {
		t.Fatalf("usage = %+v, %v; want used=2 limit=2 limited", usage.Msg, err)
	}

	if _, err := seat.RevokeSeat(ctx, req(&workspacev1.RevokeSeatRequest{Sku: "pro", UserId: "u1"})); err != nil {
		t.Fatalf("RevokeSeat: %v", err)
	}
	if holds("u1") {
		t.Fatal("revoked u1 must lose the seat tuple")
	}
	if err := assign("u3"); err != nil {
		t.Fatalf("assign u3 after revoke: %v", err)
	}
	if !holds("u3") {
		t.Fatal("u3 should hold a seat after a freed slot")
	}

	// A different tenant has its own independent (unlimited) cap.
	if _, err := seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: "z1", TenantId: "tenant-z"})); err != nil {
		t.Fatalf("assign in tenant-z must be independent of the default tenant's full cap: %v", err)
	}
}

// TestComposeConsistencyTokenReadAfterWrite verifies the consistency token
// round-trips through real Postgres sequence state: a write returns a token, a
// Check carrying it observes the just-written grant, and a malformed token is
// rejected rather than silently ignored.
func TestComposeConsistencyTokenReadAfterWrite(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	wrote, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "amy"}},
			},
		}},
	}))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	token := wrote.Msg.ConsistencyToken
	if token == "" {
		t.Fatal("WriteRelationTuples must return a consistency token")
	}

	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
		AtLeastConsistencyToken: token,
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("token-consistent check = %v, %v; want allowed", got.Msg.GetAllowed(), err)
	}

	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
		AtLeastConsistencyToken: "not-a-real-token",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed token: want InvalidArgument, got %v", err)
	}
}
