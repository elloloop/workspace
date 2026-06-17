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

func rateLimitedAuthz(t *testing.T, perMinute int) workspacev1connect.AuthzServiceClient {
	t.Helper()
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:         "default",
			ServiceAuthTokens:        []string{svcToken},
			TenantRateLimitPerMinute: perMinute,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
}

// TestExportRateBucketIsolatedFromCheck: ExportSubjectGrants is project-wide and
// rides its OWN rate bucket, so exhausting it must NOT throttle a subsequent
// (tenant-omitting) Check on the same project.
func TestExportRateBucketIsolatedFromCheck(t *testing.T) {
	authz := rateLimitedAuthz(t, 2)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := authz.ExportSubjectGrants(ctx, req(&workspacev1.ExportSubjectGrantsRequest{UserId: "u1"})); err != nil {
			t.Fatalf("export %d under cap: %v", i, err)
		}
	}
	if _, err := authz.ExportSubjectGrants(ctx, req(&workspacev1.ExportSubjectGrantsRequest{UserId: "u1"})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("export over cap should be ResourceExhausted, got %v", err)
	}
	// A Check on the same project (default tenant) uses a different bucket.
	if _, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
	})); err != nil {
		t.Fatalf("Check must not be starved by an export storm: %v", err)
	}
}

// TestDeprovisionRateProjectScoped: DeprovisionUser is project-wide; varying
// tenant_id must NOT mint a fresh bucket (no tenant-rotation evasion).
func TestDeprovisionRateProjectScoped(t *testing.T) {
	authz := rateLimitedAuthz(t, 2)
	ctx := context.Background()

	for i, tn := range []string{"ta", "tb"} { // first two (different tenants) share one project bucket
		if _, err := authz.DeprovisionUser(ctx, req(&workspacev1.DeprovisionUserRequest{UserId: "u1", TenantId: tn})); err != nil {
			t.Fatalf("deprovision %d under cap: %v", i, err)
		}
	}
	if _, err := authz.DeprovisionUser(ctx, req(&workspacev1.DeprovisionUserRequest{UserId: "u1", TenantId: "tc"})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("3rd deprovision (new tenant_id) must still draw the project bucket → ResourceExhausted, got %v", err)
	}
}

// TestNULTenantIDRejected: a NUL byte in an id can forge the bucket separator,
// so it is rejected outright (InvalidArgument), not throttled or allowed.
func TestNULTenantIDRejected(t *testing.T) {
	authz := rateLimitedAuthz(t, 60)
	_, err := authz.Check(context.Background(), req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1", TenantId: "t\x00evil",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("NUL-containing tenant_id must be InvalidArgument, got %v", err)
	}
}
