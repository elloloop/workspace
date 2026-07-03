package tests

// Backend-parameterized e2e scenarios: each scenario is written ONCE and run
// against both backends —
//
//   - memory:   the assembled handler in-process over httptest (fast, runs on
//               every `go test`), and
//   - postgres: the ACTUAL built service container on a real Postgres, reached
//               over the network, when WORKSPACES_E2E_BASE_URL is set (what
//               `make e2e-compose` boots).
//
// runOnBackends drives both. The memory subtest gets a fresh store per run, so
// it is isolated; the postgres subtest shares one database, so scenarios here
// use disjoint namespaces/object IDs (server-generated workspace/group IDs plus
// distinct fixed IDs) and never assert global counts — that keeps them safe to
// run together against the shared stack. Config-specific behavior (rate limits,
// data region, admin secret, budgets) stays in the in-process-only suites,
// since the deployed stack has one fixed configuration.

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

// runOnBackends runs scenario against the in-process memory backend always, and
// additionally against the compose Postgres stack when WORKSPACES_E2E_BASE_URL
// is set. Written once, verified on both.
func runOnBackends(t *testing.T, scenario func(*testing.T, *harness)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		scenario(t, newHarness(t))
	})
	if os.Getenv("WORKSPACES_E2E_BASE_URL") != "" {
		t.Run("postgres", func(t *testing.T) {
			scenario(t, newComposeHarness(t))
		})
	}
}

// newComposeHarness builds the same client set as newHarness, but pointed at
// the real service URL that `make e2e-compose` boots. The compose stack is
// configured with svcToken as its GATEWAY_SERVICE_AUTH_TOKENS, so the shared
// req() helper authenticates unchanged.
func newComposeHarness(t *testing.T) *harness {
	t.Helper()
	base := os.Getenv("WORKSPACES_E2E_BASE_URL")
	if base == "" {
		t.Skip("set WORKSPACES_E2E_BASE_URL (or run `make e2e-compose`) to run the full-stack compose e2e")
	}
	waitReady(t, base)
	c := http.DefaultClient
	return &harness{
		ws:    workspacev1connect.NewWorkspaceServiceClient(c, base),
		grp:   workspacev1connect.NewGroupServiceClient(c, base),
		authz: workspacev1connect.NewAuthzServiceClient(c, base),
		seat:  workspacev1connect.NewSeatServiceClient(c, base),
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

// ── scenario entrypoints ────────────────────────────────────────────────────

func TestE2ETeamWorkspaceAuthz(t *testing.T)  { runOnBackends(t, teamWorkspaceAuthzScenario) }
func TestE2EInvitationFlow(t *testing.T)       { runOnBackends(t, invitationFlowScenario) }
func TestE2EGroupsUserset(t *testing.T)        { runOnBackends(t, groupsUsersetScenario) }
func TestE2EConditionGatedCheck(t *testing.T)  { runOnBackends(t, conditionGatedScenario) }
func TestE2ESeatEnforcement(t *testing.T)      { runOnBackends(t, seatEnforcementScenario) }
func TestE2EConsistencyToken(t *testing.T)     { runOnBackends(t, consistencyReadAfterWriteScenario) }

// ── scenarios ───────────────────────────────────────────────────────────────

// teamWorkspaceAuthzScenario: create a team workspace, add a member, and verify
// the role lattice (owner ⊃ admin ⊃ member ⊃ guest) plus the member-adds-member
// deny path.
func teamWorkspaceAuthzScenario(t *testing.T, h *harness) {
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

	// owner ⊃ admin ⊃ member ⊃ guest. The subject is data, independent of the
	// acting/calling identity.
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

// invitationFlowScenario: create a workspace, invite an admin, accept the token,
// exercise the granted authority, and reject a replayed (consumed) token.
func invitationFlowScenario(t *testing.T, h *harness) {
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

	acc, err := h.ws.AcceptInvitation(ctx, req(&workspacev1.AcceptInvitationRequest{
		ActingUserId: "dad", Token: inv.Msg.Invitation.Token,
	}))
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if acc.Msg.Membership.Role != workspacev1.Role_ROLE_ADMIN {
		t.Fatalf("want ADMIN after accept, got %v", acc.Msg.Membership.Role)
	}

	if _, err := h.ws.AddMember(ctx, req(&workspacev1.AddMemberRequest{
		ActingUserId: "dad", WorkspaceId: ws.Id, UserId: "kid", Role: workspacev1.Role_ROLE_MEMBER,
	})); err != nil {
		t.Fatalf("admin AddMember: %v", err)
	}

	if _, err := h.ws.AcceptInvitation(ctx, req(&workspacev1.AcceptInvitationRequest{
		ActingUserId: "dad", Token: inv.Msg.Invitation.Token,
	})); err == nil {
		t.Fatal("want error re-accepting consumed token")
	}
}

// groupsUsersetScenario: share a resource with a whole group via a userset tuple
// (resource#viewer@group#member) and verify membership resolution.
func groupsUsersetScenario(t *testing.T, h *harness) {
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

// conditionGatedScenario: a consent-gated and an age-gated grant are evaluated
// against the CheckRequest.context end to end, and an unknown condition is
// rejected at write time.
func conditionGatedScenario(t *testing.T, h *harness) {
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
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	check := func(cc *structpb.Struct) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "course", ObjectId: "c1", Relation: "viewer", SubjectUserId: "kid", Context: cc,
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return got.Msg.Allowed
	}
	if check(nil) {
		t.Fatal("no context: consent-gated grant must deny")
	}
	if check(mustStruct(t, map[string]any{"consent": false})) {
		t.Fatal("consent=false: must deny")
	}
	if !check(mustStruct(t, map[string]any{"consent": true})) {
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

	_, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "course", ObjectId: "x", Relation: "viewer",
				Subject:       subjUser("kid"),
				ConditionName: "no_such_condition",
			},
		}},
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown condition must be rejected at write, got %v", err)
	}
}

// seatEnforcementScenario: a sku capped at N admits N and fails closed
// (ResourceExhausted) on the next; the backing seat#holder tuple gates Check; a
// revoke frees a seat; and a different tenant's cap is independent.
func seatEnforcementScenario(t *testing.T, h *harness) {
	ctx := context.Background()

	if _, err := h.seat.SetSeatLimit(ctx, req(&workspacev1.SetSeatLimitRequest{Sku: "pro", Limit: proto.Int32(2)})); err != nil {
		t.Fatalf("SetSeatLimit: %v", err)
	}
	assign := func(user string) error {
		_, err := h.seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: user}))
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
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
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

	usage, err := h.seat.GetSeatUsage(ctx, req(&workspacev1.GetSeatUsageRequest{Sku: "pro"}))
	if err != nil || usage.Msg.Used != 2 || usage.Msg.Limit != 2 || !usage.Msg.Limited {
		t.Fatalf("usage = %+v, %v; want used=2 limit=2 limited", usage.Msg, err)
	}

	if _, err := h.seat.RevokeSeat(ctx, req(&workspacev1.RevokeSeatRequest{Sku: "pro", UserId: "u1"})); err != nil {
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
	if _, err := h.seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: "z1", TenantId: "tenant-z"})); err != nil {
		t.Fatalf("assign in tenant-z must be independent of the default tenant's full cap: %v", err)
	}
}

// consistencyReadAfterWriteScenario: a write returns a token, a Check carrying
// it observes the just-written grant, and a malformed token is rejected.
func consistencyReadAfterWriteScenario(t *testing.T, h *harness) {
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
