package tests

import (
	"context"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/gen/go/workspace/v1/workspacev1connect"
	"github.com/elloloop/workspace/internal/middleware"
	"github.com/elloloop/workspace/workspaceserver"
)

// TestDecisionLogE2E: with GATEWAY_DECISION_LOG on, a Check over the API emits
// an authz_decision audit record to the structured logger, flushed on Close.
func TestDecisionLogE2E(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zap.New(core),
		Config: workspaceserver.Config{
			DefaultProjectID:  "default",
			ServiceAuthTokens: []string{svcToken},
			DecisionLog:       true,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	if _, err := authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: "d1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "amy"}},
			},
		}},
	})); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "amy",
	}))
	if err != nil || !got.Msg.Allowed {
		t.Fatalf("check = %v, %v; want allowed", got.Msg.GetAllowed(), err)
	}

	srv.Close() // flush the async decision log

	found := false
	for _, e := range logs.FilterMessage("authz_decision").All() {
		f := e.ContextMap()
		if f["subject_user"] == "amy" && f["object"] == "d1" && f["allowed"] == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("no authz_decision record for the Check (entries=%d)", logs.FilterMessage("authz_decision").Len())
	}
}

// TestDecisionCallerAttributionE2E: a Check made via a MAPPED service credential
// is recorded with that credential's caller name (resolved server-side by the
// ServiceAuth middleware), while the SAME check via the anonymous flat token is
// recorded with no caller — so a decision is attributed to the integration that
// actually performed it, never to a client-asserted value.
func TestDecisionCallerAttributionE2E(t *testing.T) {
	const slackCred = "slack-credential-token-0123456789abcdef" //nolint:gosec // test-only
	core, logs := observer.New(zapcore.InfoLevel)
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zap.New(core),
		Config: workspaceserver.Config{
			DefaultProjectID:   "default",
			ServiceAuthTokens:  []string{svcToken}, // anonymous caller
			ServiceCredentials: []middleware.ServiceCredential{{Token: slackCred, Name: "slack"}},
			DecisionLog:        true,
		},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	authz := workspacev1connect.NewAuthzServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	cr := &workspacev1.CheckRequest{Namespace: "doc", ObjectId: "d9", Relation: "viewer", SubjectUserId: "svc:slack"}
	if _, err := authz.Check(ctx, reqTok(slackCred, cr)); err != nil { // mapped caller
		t.Fatalf("slack check: %v", err)
	}
	if _, err := authz.Check(ctx, reqTok(svcToken, cr)); err != nil { // anonymous caller
		t.Fatalf("anon check: %v", err)
	}
	srv.Close()

	var sawSlack, sawAnon bool
	for _, e := range logs.FilterMessage("authz_decision").All() {
		f := e.ContextMap()
		if f["object"] != "d9" {
			continue
		}
		switch f["caller"] {
		case "slack":
			sawSlack = true
		case nil, "":
			sawAnon = true // anonymous caller → no caller field
		default:
			t.Fatalf("unexpected caller attribution: %v", f["caller"])
		}
	}
	if !sawSlack {
		t.Fatal("mapped-credential decision must be attributed to caller=slack")
	}
	if !sawAnon {
		t.Fatal("anonymous-token decision must carry no caller")
	}
}
