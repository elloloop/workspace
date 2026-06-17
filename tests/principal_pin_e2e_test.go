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
