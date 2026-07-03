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

// TestSeatNamespaceReservedOverAPI: seat-holder tuples cannot be minted through
// the generic WriteRelationTuples path — only via AssignSeat.
func TestSeatNamespaceReservedOverAPI(t *testing.T) {
	h := newHarness(t)
	_, err := h.authz.WriteRelationTuples(context.Background(), req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "seat", ObjectId: "pro", Relation: "holder",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "sneaky"}},
			},
		}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("writing a seat tuple via WriteRelationTuples must be InvalidArgument, got %v", err)
	}
}

// TestSeatListOverAPI: ListSeats returns the current assignments for a sku and
// reflects revocation — closing the coverage gap on the ListSeats RPC.
func TestSeatListOverAPI(t *testing.T) {
	srv, err := workspaceserver.New(context.Background(), workspaceserver.Options{
		Logger: zaptest.NewLogger(t),
		Config: workspaceserver.Config{DefaultProjectID: "default", ServiceAuthTokens: []string{svcToken}},
	})
	if err != nil {
		t.Fatalf("server new: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	seat := workspacev1connect.NewSeatServiceClient(hs.Client(), hs.URL)
	ctx := context.Background()

	holders := func() map[string]bool {
		resp, err := seat.ListSeats(ctx, req(&workspacev1.ListSeatsRequest{Sku: "pro"}))
		if err != nil {
			t.Fatalf("ListSeats: %v", err)
		}
		m := map[string]bool{}
		for _, s := range resp.Msg.Seats {
			if s.Sku != "pro" {
				t.Fatalf("ListSeats returned a foreign sku: %q", s.Sku)
			}
			m[s.UserId] = true
		}
		return m
	}

	// Empty to start.
	if got := holders(); len(got) != 0 {
		t.Fatalf("fresh sku should list no seats, got %v", got)
	}
	// Assign two (no limit configured = unlimited) → both listed.
	for _, u := range []string{"alice", "bob"} {
		if _, err := seat.AssignSeat(ctx, req(&workspacev1.AssignSeatRequest{Sku: "pro", UserId: u})); err != nil {
			t.Fatalf("assign %s: %v", u, err)
		}
	}
	if got := holders(); !got["alice"] || !got["bob"] || len(got) != 2 {
		t.Fatalf("ListSeats after assigns = %v, want {alice,bob}", got)
	}
	// Revoke one → no longer listed; the other remains.
	if _, err := seat.RevokeSeat(ctx, req(&workspacev1.RevokeSeatRequest{Sku: "pro", UserId: "alice"})); err != nil {
		t.Fatalf("RevokeSeat: %v", err)
	}
	if got := holders(); got["alice"] || !got["bob"] || len(got) != 1 {
		t.Fatalf("ListSeats after revoke = %v, want {bob}", got)
	}
}
