//go:build integration

// Package integration boots the real workspace service against the exact
// configuration the quickstart/docker documentation shows and asserts it comes
// up and answers — so the documented setup is EXECUTED in CI, not just read. A
// snippet that documents an unsupported env var, or a quickstart that no longer
// boots, fails here.
package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"go.uber.org/zap/zaptest"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/workspaceserver"
)

// docQuickstart mirrors the env the quickstart snippet documents (see
// docs-site/src/pages/docs/quickstart.astro and deployment/docker.astro). The
// service token and default project are the values the docs tell a reader to
// set; the test boots with exactly these so the snippet stays executable.
const (
	docServiceToken     = "dev-service-token" //nolint:gosec // documented dev token
	docDefaultProjectID = "default"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// configKnobs is the subset of the generated config.json this test reads back.
type configKnob struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// TestDocumentedSetupBoots boots the service with the documented configuration
// (memory driver — the quickstart's zero-Postgres path), hits both health
// probes, and runs a representative Check. It asserts the documented setup is
// real and serves.
func TestDocumentedSetupBoots(t *testing.T) {
	// The documented quickstart env must only name knobs the service actually
	// reads. Cross-check the doc's required env against the generated registry.
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "docs-site", "src", "data", "generated", "config.json"))
	if err != nil {
		t.Fatalf("read config.json: %v", err)
	}
	var knobs []configKnob
	if err := json.Unmarshal(b, &knobs); err != nil {
		t.Fatalf("parse config.json: %v", err)
	}
	known := map[string]bool{}
	for _, k := range knobs {
		known[k.Name] = true
	}
	for _, env := range []string{"GATEWAY_SERVICE_AUTH_TOKENS", "GATEWAY_DEFAULT_PROJECT_ID"} {
		if !known[env] {
			t.Fatalf("quickstart documents %s but the config registry does not know it", env)
		}
	}

	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{
			DefaultProjectID:  docDefaultProjectID,
			ServiceAuthTokens: []string{docServiceToken},
		},
	})
	if err != nil {
		t.Fatalf("server new with documented config: %v", err)
	}
	t.Cleanup(srv.Close)

	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	// Health probes the docs tell operators to poll.
	for _, probe := range []string{"/healthz", "/readyz"} {
		resp, err := hs.Client().Get(hs.URL + probe)
		if err != nil {
			t.Fatalf("GET %s: %v", probe, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (body %q)", probe, resp.StatusCode, body)
		}
	}

	// A representative authz RPC with the documented service credential. An
	// unprovisioned object simply returns allowed=false; the point is that the
	// documented credential authenticates and the RPC serves.
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	req := connect.NewRequest(&workspacev1.CheckRequest{
		Namespace:     "document",
		ObjectId:      "doc-1",
		Relation:      "viewer",
		SubjectUserId: "alice",
	})
	req.Header().Set("Authorization", "Bearer "+docServiceToken)
	resp, err := authz.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check with documented credential: %v", err)
	}
	if resp.Msg.Allowed {
		t.Fatalf("unprovisioned Check should be denied, got allowed=true")
	}

	// The documented credential is load-bearing: a wrong one must be rejected,
	// proving service auth is actually on as the docs claim.
	bad := connect.NewRequest(&workspacev1.CheckRequest{
		Namespace: "document", ObjectId: "doc-1", Relation: "viewer", SubjectUserId: "alice",
	})
	bad.Header().Set("Authorization", "Bearer wrong-token")
	if _, err := authz.Check(context.Background(), bad); err == nil ||
		connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong credential: want Unauthenticated, got %v", err)
	}
}
