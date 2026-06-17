package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testConsistencyToken pins the monotonic per-shard write sequence that backs
// read-after-write: it starts at 0, strictly increases on each WriteTuples, and
// is isolated per (project, tenant) — identically across drivers.
func testConsistencyToken(t *testing.T, r service.Repository) {
	t.Helper()
	const p, t1, t2 = "proj", "tenantA", "tenantB"

	seq := func(tenant string) int64 {
		v, err := r.ConsistencyToken(ctx(), p, tenant)
		if err != nil {
			t.Fatalf("ConsistencyToken(%s): %v", tenant, err)
		}
		return v
	}
	write := func(tenant, obj string) int64 {
		if err := r.WriteTuples(ctx(), p, tenant, []authz.Tuple{userTuple("doc", obj, "viewer", "u1")}, nil); err != nil {
			t.Fatalf("WriteTuples: %v", err)
		}
		return seq(tenant)
	}

	// A never-written shard is at 0.
	if got := seq(t1); got != 0 {
		t.Fatalf("fresh shard seq = %d, want 0", got)
	}

	// Each write to t1 strictly advances its sequence.
	first := write(t1, "a")
	if first <= 0 {
		t.Fatalf("seq after first write = %d, want > 0", first)
	}
	if second := write(t1, "b"); second <= first {
		t.Fatalf("seq must strictly increase: first=%d second=%d", first, second)
	}
	t1now := seq(t1)

	// t2 has its own independent sequence, unaffected by t1's writes.
	if got := seq(t2); got != 0 {
		t.Fatalf("sibling tenant seq = %d, want 0 (isolated)", got)
	}
	if t2first := write(t2, "a"); t2first != 1 {
		t.Fatalf("first write to t2 seq = %d, want 1 (independent counter)", t2first)
	}
	// t1 is unmoved by t2's write.
	if got := seq(t1); got != t1now {
		t.Fatalf("t1 seq moved due to a t2 write: %d != %d", got, t1now)
	}

	// The sequence advances for EVERY tuple-mutating write, not just the generic
	// WriteTuples path — membership, enrollment, and seat writes all count, so a
	// caller acting on a member can then read-after-write with the token.
	bumps := func(label string, mutate func()) {
		before := seq(t1)
		mutate()
		if after := seq(t1); after <= before {
			t.Fatalf("%s did not advance the consistency seq: before=%d after=%d", label, before, after)
		}
	}
	bumps("PutMembershipAndTuples", func() {
		m := &service.Membership{
			ProjectID: p, TenantID: t1, WorkspaceID: "wc", UserID: "uc",
			Role: service.RoleMember, Status: service.StatusActive,
		}
		if err := r.PutMembershipAndTuples(ctx(), m, []authz.Tuple{userTuple("workspace", "wc", "member", "uc")}, nil); err != nil {
			t.Fatalf("PutMembershipAndTuples: %v", err)
		}
	})
	bumps("AssignSeatAndTuple", func() {
		a := &service.SeatAssignment{ProjectID: p, TenantID: t1, SKU: "pro", UserID: "uc"}
		if _, err := r.AssignSeatAndTuple(ctx(), a, authz.Tuple{
			Namespace: "seat", ObjectID: "pro", Relation: "holder", Subject: authz.Subject{UserID: "uc"},
		}); err != nil {
			t.Fatalf("AssignSeatAndTuple: %v", err)
		}
	})
	bumps("SetEnrollmentAndTuples", func() {
		if err := r.CreateGroup(ctx(), &service.Group{ID: "co", ProjectID: p, TenantID: t1, Slug: "co", DisplayName: "co"}); err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		e := &service.Enrollment{
			ProjectID: p, TenantID: t1, GroupID: "co", Member: service.GroupMember{UserID: "uc"},
			State: service.EnrollmentActive,
		}
		if err := r.SetEnrollmentAndTuples(ctx(), e, []authz.Tuple{userTuple("group", "co", "member", "uc")}, nil); err != nil {
			t.Fatalf("SetEnrollmentAndTuples: %v", err)
		}
	})
}
