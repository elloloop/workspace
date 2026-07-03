package tests

// Config-specific full-stack e2e scenarios. These exercise behavior that
// depends on the SERVICE CONFIGURATION, so they can't share the one generic
// compose stack the TestE2E scenarios use — they run against dedicated compose
// profiles (`make e2e-compose-config` and `make e2e-compose-ratelimit`), which
// boot the same image with profile-specific GATEWAY_* env.
//
// They are postgres-only: each skips unless WORKSPACES_E2E_BASE_URL is set
// (the in-process suites — data_residency/read_budget/tenant_ratelimit/
// configurable — already cover these behaviors on the memory driver; the value
// here is verifying them through the deployed image on real Postgres). The
// profile's make target sets the matching env AND the `-run` filter, so each
// test only runs against a stack configured for it.

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// ── featured profile (make e2e-compose-config): admin API on, instance region
//    us-east-1, MaxListObjects=2, MaxBatchCheckItems=2 ─────────────────────────

// TestFeaturedAdminProjectConfig: the AdminService project-config surface
// round-trips against real Postgres, and is gated by the X-Admin-Secret header.
func TestFeaturedAdminProjectConfig(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "feat-proj", Name: "Featured",
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	got, err := h.admin.GetProject(ctx, reqAdmin(&workspacev1.GetProjectRequest{Id: "feat-proj"}))
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if got.Msg.Project.GetName() != "Featured" {
		t.Fatalf("GetProject name = %q, want Featured", got.Msg.Project.GetName())
	}

	// Service token without the admin secret → Unauthenticated.
	if _, err := h.admin.GetProject(ctx, req(&workspacev1.GetProjectRequest{Id: "feat-proj"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("GetProject without admin secret: want Unauthenticated, got %v", err)
	}
}

// TestFeaturedDataResidency: the instance (pinned to us-east-1) refuses a
// project pinned to another region, while still serving the region-agnostic
// default project — fail-closed residency enforcement through the real stack.
func TestFeaturedDataResidency(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "eu-proj", Name: "EU", DataRegion: "eu-west-1",
	})); err != nil {
		t.Fatalf("CreateProject eu: %v", err)
	}

	// A project-scoped RPC on the mismatched region fails closed.
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		ProjectId: "eu-proj", Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("check on foreign-region project: want FailedPrecondition, got %v", err)
	}

	// The region-agnostic default project is still served (no residency error).
	if _, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1",
	})); err != nil {
		t.Fatalf("check on region-agnostic default project must be served: %v", err)
	}
}

// TestFeaturedBatchCheckCap: a BatchCheck exceeding MaxBatchCheckItems (2) is
// rejected at the handler boundary.
func TestFeaturedBatchCheckCap(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	item := &workspacev1.BatchCheckItem{Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: "a"}
	if _, err := h.authz.BatchCheck(ctx, req(&workspacev1.BatchCheckRequest{
		Items: []*workspacev1.BatchCheckItem{item, item, item},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("batch over cap: want InvalidArgument, got %v", err)
	}
}

// TestFeaturedListObjectsCap: a ListObjects whose candidate set exceeds
// MaxListObjects (2) fails closed with ResourceExhausted.
func TestFeaturedListObjectsCap(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	var ups []*workspacev1.TupleUpdate
	for _, o := range []string{"lo1", "lo2", "lo3"} {
		ups = append(ups, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "doc", ObjectId: o, Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "amy-lo"}},
			},
		})
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{Updates: ups})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}
	if _, err := h.authz.ListObjects(ctx, req(&workspacev1.ListObjectsRequest{
		Namespace: "doc", Relation: "viewer", SubjectUserId: "amy-lo",
	})); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("ListObjects over cap: want ResourceExhausted, got %v", err)
	}
}

// TestFeaturedReadBudgetConfig: a valid per-project MaxCheckReads override
// persists through real Postgres, and a sub-floor override is rejected.
func TestFeaturedReadBudgetConfig(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "rich", Name: "Rich", MaxCheckReads: 5000,
	})); err != nil {
		t.Fatalf("CreateProject rich: %v", err)
	}
	got, err := h.admin.GetProject(ctx, reqAdmin(&workspacev1.GetProjectRequest{Id: "rich"}))
	if err != nil || got.Msg.Project.GetMaxCheckReads() != 5000 {
		t.Fatalf("GetProject rich max_check_reads = %v, %v; want 5000", got.Msg.Project.GetMaxCheckReads(), err)
	}

	// A sub-floor override (< MinMaxCheckReads = 100) is rejected.
	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "bad", Name: "Bad", MaxCheckReads: 50,
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("sub-floor max_check_reads: want InvalidArgument, got %v", err)
	}
}

// ── rate-limit profile (make e2e-compose-ratelimit): TenantRateLimitPerMinute
//    = 60 ───────────────────────────────────────────────────────────────────

// TestRateLimitComposeTenant: the per-(project, tenant) authz rate limiter
// admits then fails closed under load, and a second tenant has an independent
// bucket — verified through the deployed stack.
//
// The limiter is a token bucket (capacity 60, refill 1/sec), so an EXACT
// "Nth call is the one that trips" assertion is wall-clock fragile: if the
// burst spans ~1s a token refills and shifts the boundary. Instead we fire a
// burst far larger than the capacity as fast as possible — refill over the
// burst is negligible against that excess, so throttling is guaranteed — and
// assert (a) the first call is admitted (fresh bucket) and (b) at least one
// call is throttled with ResourceExhausted.
func TestRateLimitComposeTenant(t *testing.T) {
	h := newComposeHarness(t)
	ctx := context.Background()

	check := func(tenant string) error {
		_, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "workspace", ObjectId: "w1", Relation: "member", SubjectUserId: "u1", TenantId: tenant,
		}))
		return err
	}

	// Fresh bucket: the first call is admitted.
	if err := check("rl"); err != nil {
		t.Fatalf("first call on tenant rl should succeed, got %v", err)
	}

	// Burst well past the 60-token capacity; count throttled responses.
	const burst = 200
	rejected := 0
	for i := 0; i < burst; i++ {
		if err := check("rl"); err != nil {
			if connect.CodeOf(err) != connect.CodeResourceExhausted {
				t.Fatalf("tenant rl call %d: want nil or ResourceExhausted, got %v", i, err)
			}
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatalf("a burst of %d rapid calls on one tenant was never throttled; the 60/min limiter is not enforcing", burst)
	}

	// A different tenant has an independent bucket: its first call is admitted
	// even though tenant rl is exhausted.
	if err := check("rl2"); err != nil {
		t.Fatalf("first call on tenant rl2 should succeed (independent bucket): %v", err)
	}
}
