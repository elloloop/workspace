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

// TestSeatEnforcementOverAPI: a sku capped at N admits N seat assignments and
// fails closed (ResourceExhausted) on the next; a revoke frees a seat; the
// backing seat:<sku>#holder tuple makes a seat-holder visible to Check; and seat
// usage reports used/limit.
func TestSeatEnforcementOverAPI(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{DefaultProjectID: "default", ServiceAuthTokens: []string{svcToken}},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	c := hs.Client()
	seat := workspacev1connect.NewSeatServiceClient(c, hs.URL)
	authz := workspacev1connect.NewAuthzServiceClient(c, hs.URL)
	ctx := context.Background()

	if _, err := seat.SetSeatLimit(ctx, req(&workspacev1.SetSeatLimitRequest{Sku: "pro", Limit: 2})); err != nil {
		t.Fatalf("SetSeatLimit: %v", err)
	}
	assign := func(user string) error {
		_, err := seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: user}))
		return err
	}
	if err := assign("u1"); err != nil {
		t.Fatalf("assign u1: %v", err)
	}
	if err := assign("u2"); err != nil {
		t.Fatalf("assign u2: %v", err)
	}
	// Over the cap → ResourceExhausted.
	if err := assign("u3"); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("assign u3 over cap: want ResourceExhausted, got %v", err)
	}

	// A seat-holder is visible to Check via seat:pro#holder.
	holds := func(user string) bool {
		got, err := authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "seat", ObjectId: "pro", Relation: "holder", SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s: %v", user, err)
		}
		return got.Msg.Allowed
	}
	if !holds("u1") || holds("u3") {
		t.Fatalf("seat tuple gate: u1=%v (want true) u3=%v (want false)", holds("u1"), holds("u3"))
	}

	// Usage reports 2/2.
	usage, err := seat.GetSeatUsage(ctx, req(&workspacev1.GetSeatUsageRequest{Sku: "pro"}))
	if err != nil || usage.Msg.Used != 2 || usage.Msg.Limit != 2 || !usage.Msg.Limited {
		t.Fatalf("usage = %+v, %v; want used=2 limit=2 limited", usage.Msg, err)
	}

	// Revoke frees a seat; u3 now fits and loses-then-gains the tuple gate.
	if _, err := seat.RevokeSeat(ctx, req(&workspacev1.RevokeSeatRequest{Sku: "pro", UserId: "u1"})); err != nil {
		t.Fatalf("RevokeSeat: %v", err)
	}
	if holds("u1") {
		t.Fatal("revoked u1 must lose the seat tuple")
	}
	if err := assign("u3"); err != nil {
		t.Fatalf("assign u3 after revoke: %v", err)
	}
	if !holds("u3") {
		t.Fatal("u3 should hold a seat after a freed slot")
	}
}
