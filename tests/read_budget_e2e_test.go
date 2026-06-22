package tests

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/workspaceserver"
)

// budgetHarness is an admin+authz harness with a deliberately STINGY global
// read budget, so a per-project max_check_reads override is observable.
type budgetHarness struct {
	authz workspacev1connect.AuthzServiceClient
	admin workspacev1connect.AdminServiceClient
}

func newBudgetHarness(t *testing.T, globalMaxReads int) *budgetHarness {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken},
			AdminAPISecret:    adminSecret,
			MaxCheckReads:     globalMaxReads,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return &budgetHarness{
		authz: workspacev1connect.NewAuthzServiceClient(c, hs.URL),
		admin: workspacev1connect.NewAdminServiceClient(c, hs.URL),
	}
}

// wideModelJSON resolves res#viewer through a tuple-to-userset over `parent`
// into a separate leafns namespace, so a Check reads one tuple per leaf.
const wideModelJSON = `{` +
	`"res":{"parent":{"this":true},"viewer":{"tupleToUserset":{"tupleset":"parent","computed":"leaf"}}},` +
	`"leafns":{"leaf":{"this":true}}}`

// seedWideProject wires res:root with n leaf pointers (each granting only bob,
// never the queried alice) so an alice Check reads every leaf before denying.
func (h *budgetHarness) seedWideProject(ctx context.Context, t *testing.T, projectID string, n int) {
	t.Helper()
	var ups []*workspacev1.TupleUpdate
	for i := 0; i < n; i++ {
		leaf := fmt.Sprintf("leaf%d", i)
		ups = append(ups, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				ProjectId: projectID, Namespace: "res", ObjectId: "root", Relation: "parent",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "leafns", ObjectId: leaf, Relation: "leaf",
				}}},
			},
		})
		ups = append(ups, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				ProjectId: projectID, Namespace: "leafns", ObjectId: leaf, Relation: "leaf",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "bob"}},
			},
		})
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		ProjectId: projectID, Updates: ups,
	})); err != nil {
		t.Fatalf("seed %s: %v", projectID, err)
	}
}

// TestPerProjectReadBudgetE2E exercises the override end-to-end over the
// AdminService + AuthzService: with a stingy global budget, a project carrying a
// high max_check_reads override completes a read-heavy Check that an
// override-free project trips on (ResourceExhausted). It also asserts the
// override round-trips on GetProject and that clearing it reverts to the global
// default.
func TestPerProjectReadBudgetE2E(t *testing.T) {
	ctx := context.Background()
	h := newBudgetHarness(t, 100) // stingy global default

	// "rich" overrides the budget; "plain" stays on the global default.
	createResp, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "rich", Name: "Rich", ModelJson: wideModelJSON, MaxCheckReads: 5000,
	}))
	if err != nil {
		t.Fatalf("CreateProject rich: %v", err)
	}
	if createResp.Msg.Project.MaxCheckReads != 5000 {
		t.Fatalf("create returned budget %d, want 5000", createResp.Msg.Project.MaxCheckReads)
	}
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "plain", Name: "Plain", ModelJson: wideModelJSON, MaxCheckReads: 0,
	})); err != nil {
		t.Fatalf("CreateProject plain: %v", err)
	}

	// GetProject round-trips the override.
	got, err := h.admin.GetProject(ctx, reqAdmin(&workspacev1.GetProjectRequest{Id: "rich"}))
	if err != nil || got.Msg.Project.MaxCheckReads != 5000 {
		t.Fatalf("GetProject rich budget = %v, %v; want 5000", got.Msg.Project.GetMaxCheckReads(), err)
	}

	h.seedWideProject(ctx, t, "rich", 300)
	h.seedWideProject(ctx, t, "plain", 300)

	// The override project completes the read-heavy Check.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		ProjectId: "rich", Namespace: "res", ObjectId: "root", Relation: "viewer", SubjectUserId: "alice",
	})); err != nil {
		t.Fatalf("rich Check (override 5000) must complete, got %v", err)
	}

	// The override-free project trips the stingy global budget.
	_, err = h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		ProjectId: "plain", Namespace: "res", ObjectId: "root", Relation: "viewer", SubjectUserId: "alice",
	}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("plain Check (global default) = %v, want CodeResourceExhausted", err)
	}

	// A sub-floor override is rejected.
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "bad", Name: "Bad", MaxCheckReads: 5,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("sub-floor override = %v, want CodeInvalidArgument", err)
	}

	// Clearing the override reverts the project to the global default budget. The
	// resolver caches for ~30s, so this asserts the persisted/returned value
	// rather than re-checking (which would race the cache TTL).
	upd, err := h.admin.UpdateProject(ctx, reqAdmin(&workspacev1.UpdateProjectRequest{
		Id: "rich", ClearMaxCheckReads: true,
	}))
	if err != nil || upd.Msg.Project.MaxCheckReads != 0 {
		t.Fatalf("clear override = %v, %v; want 0", upd.Msg.Project.GetMaxCheckReads(), err)
	}
	reGot, err := h.admin.GetProject(ctx, reqAdmin(&workspacev1.GetProjectRequest{Id: "rich"}))
	if err != nil || reGot.Msg.Project.MaxCheckReads != 0 {
		t.Fatalf("after clear GetProject budget = %v, %v; want 0 (global default)", reGot.Msg.Project.GetMaxCheckReads(), err)
	}
}
