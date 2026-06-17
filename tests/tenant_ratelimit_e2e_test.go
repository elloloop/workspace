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

// TestTenantRateLimit: authz RPCs are throttled per (project, tenant). One
// tenant exceeding its per-minute cap gets ResourceExhausted while a different
// tenant in the same project, with its own bucket, is unaffected.
func TestTenantRateLimit(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:         "default",
			ServiceAuthTokens:        []string{svcToken},
			TenantRateLimitPerMinute: 2,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	check := func(tenant string) error {
		_, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1", TenantId: tenant,
		}))
		return err
	}

	// Tenant t1: two calls under the cap succeed, the third is throttled.
	for i := 0; i < 2; i++ {
		if err := check("t1"); err != nil {
			t.Fatalf("t1 call %d under the cap should succeed: %v", i, err)
		}
	}
	if err := check("t1"); err == nil || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("t1 over the cap should be ResourceExhausted, got %v", err)
	}

	// A different tenant in the same project has an independent bucket.
	if err := check("t2"); err != nil {
		t.Fatalf("t2 (separate per-tenant bucket) should not be throttled: %v", err)
	}
}

// TestTenantRateLimitDisabled: with the limit at 0 (default), there is no cap.
func TestTenantRateLimitDisabled(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{DefaultProjectID: "default", ServiceAuthTokens: []string{svcToken}},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	for i := 0; i < 50; i++ {
		if _, err := authz.Check(context.Background(), req(&workspacev1.CheckRequest{
			Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
		})); err != nil {
			t.Fatalf("call %d with limiter disabled should never throttle: %v", i, err)
		}
	}
}
