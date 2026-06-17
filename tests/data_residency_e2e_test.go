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

type regionHarness struct {
	authz workspacev1connect.AuthzServiceClient
	admin workspacev1connect.AdminServiceClient
}

// newRegionHarness builds a server pinned to instanceRegion (empty = agnostic),
// with the admin API enabled so a test can configure projects' data_region.
func newRegionHarness(t *testing.T, instanceRegion string) *regionHarness {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken},
			AdminAPISecret:    adminSecret,
			DataRegion:        instanceRegion,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	return &regionHarness{
		authz: workspacev1connect.NewAuthzServiceClient(c, hs.URL),
		admin: workspacev1connect.NewAdminServiceClient(c, hs.URL),
	}
}

// TestDataResidencyGuard: an instance pinned to a region serves only projects
// whose data_region matches (or is unset), and fails closed (FailedPrecondition)
// on a project pinned elsewhere — while a region-agnostic instance serves all.
func TestDataResidencyGuard(t *testing.T) {
	h := newRegionHarness(t, "us-east-1")
	ctx := context.Background()

	// A project pinned to a DIFFERENT region than this instance.
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "eu-proj", Name: "EU", DataRegion: "eu-west-1",
	})); err != nil {
		t.Fatalf("CreateProject eu-proj: %v", err)
	}
	// A project pinned to THIS instance's region.
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "us-proj", Name: "US", DataRegion: "us-east-1",
	})); err != nil {
		t.Fatalf("CreateProject us-proj: %v", err)
	}
	// An unpinned project (no data_region).
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "any-proj", Name: "Any",
	})); err != nil {
		t.Fatalf("CreateProject any-proj: %v", err)
	}

	check := func(project string) error {
		_, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			ProjectId: project, Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
		}))
		return err
	}

	// Mismatched region → fail closed.
	if err := check("eu-proj"); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("eu-proj on a us-east-1 instance: want FailedPrecondition, got %v", err)
	}
	// Matching region and unpinned project → served (a denied Check returns no
	// error; the point is the region guard does not reject).
	if err := check("us-proj"); err != nil {
		t.Fatalf("us-proj on a matching instance must be served: %v", err)
	}
	if err := check("any-proj"); err != nil {
		t.Fatalf("unpinned project must be served: %v", err)
	}

	// A write to the mismatched project is also refused.
	_, werr := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		ProjectId: "eu-proj",
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "u1"}},
			},
		}},
	}))
	if connect.CodeOf(werr) != connect.CodeFailedPrecondition {
		t.Fatalf("write to eu-proj on a us-east-1 instance: want FailedPrecondition, got %v", werr)
	}
}

// TestDataResidencyAgnosticServesAll: an instance with no GATEWAY_DATA_REGION
// serves a region-pinned project unchanged (today's behavior).
func TestDataResidencyAgnosticServesAll(t *testing.T) {
	h := newRegionHarness(t, "") // region-agnostic
	ctx := context.Background()

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "eu-proj", Name: "EU", DataRegion: "eu-west-1",
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		ProjectId: "eu-proj", Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
	})); err != nil {
		t.Fatalf("region-agnostic instance must serve a pinned project: %v", err)
	}

	// Malformed region is rejected at config time.
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "bad", Name: "Bad", DataRegion: "US East!",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed data_region: want InvalidArgument, got %v", err)
	}
}
