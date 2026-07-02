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

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
)

// newComposeHarness builds the same client set as newHarness, but pointed at
// the real service URL that `make e2e-compose` boots. The compose stack is
// configured with svcToken as its GATEWAY_SERVICE_AUTH_TOKENS, so the shared
// req() helper (which presents that token) authenticates unchanged.
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
