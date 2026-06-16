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

// TestSuspendedProjectDeniesAndUpdateIsPatch covers two gate blockers: a
// suspended project must fail closed (Check denies, writes rejected), and a
// status-only UpdateProject must NOT wipe the project's custom model/name.
func TestSuspendedProjectDeniesAndUpdateIsPatch(t *testing.T) {
	h := newAdminHarness(t)
	ctx := context.Background()
	const model = `{"course":{"viewer":{"this":true}}}`

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "p2", Name: "Kids", ModelJson: model,
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	grant := []*workspacev1.TupleUpdate{{
		Op:    workspacev1.TupleUpdate_OP_INSERT,
		Tuple: &workspacev1.RelationTuple{ProjectId: "p2", Namespace: "course", ObjectId: "c1", Relation: "viewer", Subject: subjUser("amy")},
	}}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{ProjectId: "p2", Updates: grant})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}
	mustCheck := func(want bool) {
		t.Helper()
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			ProjectId: "p2", Namespace: "course", ObjectId: "c1", Relation: "viewer", SubjectUserId: "amy",
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got.Msg.Allowed != want {
			t.Fatalf("allowed=%v want %v", got.Msg.Allowed, want)
		}
	}
	mustCheck(true)

	// Suspend WITHOUT re-sending name/model: patch semantics must preserve them.
	upd, err := h.admin.UpdateProject(ctx, reqAdmin(&workspacev1.UpdateProjectRequest{
		Id: "p2", Status: workspacev1.ProjectStatus_PROJECT_STATUS_SUSPENDED,
	}))
	if err != nil {
		t.Fatalf("UpdateProject suspend: %v", err)
	}
	if upd.Msg.Project.ModelJson == "" {
		t.Fatal("status-only update wiped the custom model")
	}
	if upd.Msg.Project.Name != "Kids" {
		t.Fatalf("status-only update wiped the name: %q", upd.Msg.Project.Name)
	}

	// Suspended project fails closed: Check denies, writes are rejected.
	mustCheck(false)
	_, werr := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{ProjectId: "p2", Updates: grant}))
	if werr == nil || connect.CodeOf(werr) != connect.CodeFailedPrecondition {
		t.Fatalf("write to suspended project: want FailedPrecondition, got %v", werr)
	}

	// Reinstating restores access (and still preserves the model).
	if _, err := h.admin.UpdateProject(ctx, reqAdmin(&workspacev1.UpdateProjectRequest{
		Id: "p2", Status: workspacev1.ProjectStatus_PROJECT_STATUS_ACTIVE,
	})); err != nil {
		t.Fatalf("UpdateProject reinstate: %v", err)
	}
	mustCheck(true)
}

// TestDefaultTenantWiring: with GATEWAY_DEFAULT_TENANT_ID configured, a request
// that omits tenant_id lands in the configured default tenant.
func TestDefaultTenantWiring(t *testing.T) {
	authz, ws := customServer(t, workspaceserver.Config{
		DefaultProjectID:  "default",
		DefaultTenantID:   "acme",
		ServiceAuthTokens: []string{svcToken},
	})
	ctx := context.Background()

	created, err := ws.CreateWorkspace(ctx, req(&workspacev1.CreateWorkspaceRequest{
		ActingUserId: "alice", DisplayName: "Acme",
	}))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if created.Msg.Workspace.TenantId != "acme" {
		t.Fatalf("omitted tenant_id landed in %q, want the configured default 'acme'", created.Msg.Workspace.TenantId)
	}
	// The owner tuple is reachable in the default tenant with tenant_id omitted.
	got, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: created.Msg.Workspace.Id, Relation: "owner", SubjectUserId: "alice",
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("owner check in default tenant = %v, %v", got.Msg.Allowed, err)
	}
}

// TestListObjectsCap: a namespace larger than GATEWAY_MAX_LIST_OBJECTS is
// rejected rather than scanned unboundedly.
func TestListObjectsCap(t *testing.T) {
	authz, _ := customServer(t, workspaceserver.Config{
		DefaultProjectID:  "default",
		ServiceAuthTokens: []string{svcToken},
		MaxListObjects:    2,
	})
	ctx := context.Background()

	var writes []*workspacev1.TupleUpdate
	for _, id := range []string{"c1", "c2", "c3"} {
		writes = append(writes, &workspacev1.TupleUpdate{
			Op:    workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{Namespace: "doc", ObjectId: id, Relation: "viewer", Subject: subjUser("amy")},
		})
	}
	if _, err := authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{Updates: writes})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}
	_, err := authz.ListObjects(ctx, req(&workspacev1.ListObjectsRequest{
		Namespace: "doc", Relation: "viewer", SubjectUserId: "amy",
	}))
	if err == nil || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("ListObjects over cap: want ResourceExhausted, got %v", err)
	}
}

func customServer(t *testing.T, cfg workspaceserver.Config) (workspacev1connect.AuthzServiceClient, workspacev1connect.WorkspaceServiceClient) {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return workspacev1connect.NewAuthzServiceClient(c, hs.URL), workspacev1connect.NewWorkspaceServiceClient(c, hs.URL)
}
