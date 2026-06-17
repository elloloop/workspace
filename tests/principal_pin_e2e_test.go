package tests

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/internal/middleware"
	"github.com/elloloop/workspace/workspaceserver"
)

// reqTok presents an arbitrary bearer credential (instead of the default flat
// svcToken), so a test can call as a specific mapped service credential.
func reqTok[T any](token string, msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer "+token)
	return r
}

// TestServiceCredentialProjectPin: a credential pinned to a project has all of
// its requests FORCED into that project, regardless of the request's project_id,
// so an integration cannot operate outside its assigned project. An unpinned
// (flat-token) caller targets whatever project it asks for.
func TestServiceCredentialProjectPin(t *testing.T) {
	const slackCred = "slack-credential-token" //nolint:gosec // test-only credential
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken}, // unpinned caller
			ServiceCredentials: []middleware.ServiceCredential{
				{Token: slackCred, Name: "slack", ProjectID: "slack-proj"},
			},
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	// The slack credential writes a grant while ASKING for a different project —
	// the pin forces it into "slack-proj" instead.
	if _, err := authz.WriteRelationTuples(ctx, reqTok(slackCred, &workspacev1.WriteRelationTuplesRequest{
		ProjectId: "attacker-chosen-project",
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "alice"}},
			},
		}},
	})); err != nil {
		t.Fatalf("pinned write: %v", err)
	}

	check := func(req *connect.Request[workspacev1.CheckRequest]) bool {
		got, err := authz.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return got.Msg.Allowed
	}
	cr := func(project string) *workspacev1.CheckRequest {
		return &workspacev1.CheckRequest{Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "alice", ProjectId: project}
	}

	// The grant landed in slack-proj (the pin), NOT the attacker-chosen project:
	// an unpinned caller sees it in slack-proj but not in attacker-chosen-project.
	if !check(reqTok(svcToken, cr("slack-proj"))) {
		t.Fatal("pinned write should have landed in slack-proj")
	}
	if check(reqTok(svcToken, cr("attacker-chosen-project"))) {
		t.Fatal("pinned write must NOT have landed in the attacker-chosen project")
	}
	// Reads from the slack credential are pinned too: it sees its grant even when
	// it asks for a different project.
	if !check(reqTok(slackCred, cr("some-other-project"))) {
		t.Fatal("slack credential's reads must be forced into slack-proj")
	}
}

// pinHarness builds a server with one project-pinned credential plus the flat
// (unpinned) svcToken, returning clients for the pinned and unpinned callers.
func pinHarness(t *testing.T, cred, name, pin string) (*httptest.Server, string) {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:   "default",
			ServiceAuthTokens:  []string{svcToken},
			ServiceCredentials: []middleware.ServiceCredential{{Token: cred, Name: name, ProjectID: pin}},
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, pin
}

// TestPinForcesManagementRPCProject: a pinned credential's management RPCs are
// forced into its project — a created workspace lands in the pin, and it cannot
// see or destroy a workspace that belongs to a different (unpinned) project.
func TestPinForcesManagementRPCProject(t *testing.T) {
	const slackCred = "slack-credential-token-0123456789abcdef" //nolint:gosec // test-only
	hs, pin := pinHarness(t, slackCred, "slack", "slack-proj")
	ws := workspacev1connect.NewWorkspaceServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	// (a) CreateWorkspace while asking for another project → forced into the pin.
	created, err := ws.CreateWorkspace(ctx, reqTok(slackCred, &workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Slack WS", ProjectId: "attacker-chosen-project",
	}))
	if err != nil {
		t.Fatalf("pinned CreateWorkspace: %v", err)
	}
	if created.Msg.Workspace.ProjectId != pin {
		t.Fatalf("created workspace project = %q, want pinned %q", created.Msg.Workspace.ProjectId, pin)
	}

	// (b) An unpinned caller creates a workspace in "default". The pinned caller
	//     must NOT be able to find/destroy it (its lookups are forced to slack-proj).
	other, err := ws.CreateWorkspace(ctx, reqTok(svcToken, &workspacev1.CreateWorkspaceRequest{
		ActingUserId: "bob", DisplayName: "Default WS", ProjectId: "default",
	}))
	if err != nil {
		t.Fatalf("unpinned CreateWorkspace: %v", err)
	}
	_, err = ws.DeleteWorkspace(ctx, reqTok(slackCred, &workspacev1.DeleteWorkspaceRequest{
		ActingUserId: "alice", WorkspaceId: other.Msg.Workspace.Id, ProjectId: "default",
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("pinned caller must not find another project's workspace; got %v", err)
	}
}

// TestPinScopesExportSubjectGrants: ExportSubjectGrants from a pinned credential
// returns ONLY the pinned project's grants, never another project's — the
// highest-blast-radius cross-project read stays scoped to the pin.
func TestPinScopesExportSubjectGrants(t *testing.T) {
	const slackCred = "slack-credential-token-0123456789abcdef" //nolint:gosec // test-only
	hs, _ := pinHarness(t, slackCred, "slack", "slack-proj")
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	grant := func(token, project, obj string) {
		if _, err := authz.WriteRelationTuples(ctx, reqTok(token, &workspacev1.WriteRelationTuplesRequest{
			ProjectId: project,
			Updates: []*workspacev1.TupleUpdate{{
				Op: workspacev1.TupleUpdate_OP_INSERT,
				Tuple: &workspacev1.RelationTuple{
					Namespace: "doc", ObjectId: obj, Relation: "viewer",
					Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "alice"}},
				},
			}},
		})); err != nil {
			t.Fatalf("grant %s/%s: %v", project, obj, err)
		}
	}
	grant(slackCred, "ignored-by-pin", "in-slack") // forced into slack-proj
	grant(svcToken, "other-proj", "in-other")      // unpinned, a different project

	// Export from the pinned credential (asking for yet another project) sees
	// only slack-proj's grant.
	resp, err := authz.ExportSubjectGrants(ctx, reqTok(slackCred, &workspacev1.ExportSubjectGrantsRequest{
		UserId: "alice", ProjectId: "some-other-project",
	}))
	if err != nil {
		t.Fatalf("ExportSubjectGrants: %v", err)
	}
	for _, g := range resp.Msg.Grants {
		if g.ObjectId == "in-other" {
			t.Fatal("pinned export leaked another project's grant")
		}
	}
	if len(resp.Msg.Grants) == 0 {
		t.Fatal("pinned export should include the slack-proj grant")
	}
}
