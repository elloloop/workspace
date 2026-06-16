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

// TestAdminRateLimit: the admin surface is throttled per caller — calls within
// the per-minute cap succeed, the one over it gets ResourceExhausted.
func TestAdminRateLimit(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:        "default",
			ServiceAuthTokens:       []string{svcToken},
			AdminAPISecret:          adminSecret,
			AdminRateLimitPerMinute: 2,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	admin := workspacev1connect.NewAdminServiceClient(hs.Client(), hs.URL)

	for i := 0; i < 2; i++ {
		if _, err := admin.ListProjects(context.Background(), reqAdmin(&workspacev1.ListProjectsRequest{})); err != nil {
			t.Fatalf("admin call %d under the limit should succeed: %v", i, err)
		}
	}
	_, err = admin.ListProjects(context.Background(), reqAdmin(&workspacev1.ListProjectsRequest{}))
	if err == nil || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("admin call over the limit should be ResourceExhausted, got %v", err)
	}
}
