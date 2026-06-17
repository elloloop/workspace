package conformance

import (
	"errors"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testAtomicMembership pins the transactional membership+tuple writes: the
// membership row and its backing role tuple always land (and leave) together,
// and a membership-not-found delete rolls back without touching any tuple.
func testAtomicMembership(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	m := &service.Membership{
		ProjectID: p, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleAdmin, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	}
	roleTuple := userTuple("workspace", "w1", "admin", "u1")

	// PutMembershipAndTuples: the row and the tuple land together.
	if err := r.PutMembershipAndTuples(ctx(), m, []authz.Tuple{roleTuple}, nil); err != nil {
		t.Fatalf("PutMembershipAndTuples: %v", err)
	}
	if _, err := r.GetMembership(ctx(), p, "", "w1", "u1"); err != nil {
		t.Fatalf("membership missing after atomic put: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "workspace", "w1", "admin"); len(subs) != 1 || subs[0].UserID != "u1" {
		t.Fatalf("role tuple missing after atomic put: %+v", subs)
	}

	// DeleteMembershipAndTuples: both gone together.
	if err := r.DeleteMembershipAndTuples(ctx(), p, "", "w1", "u1", []authz.Tuple{roleTuple}); err != nil {
		t.Fatalf("DeleteMembershipAndTuples: %v", err)
	}
	if _, err := r.GetMembership(ctx(), p, "", "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("membership still present after atomic delete: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "workspace", "w1", "admin"); len(subs) != 0 {
		t.Fatalf("role tuple still present after atomic delete: %+v", subs)
	}

	// Rollback: deleting an absent membership returns ErrNotFound and must NOT
	// apply the accompanying tuple delete (neither side changes).
	keep := userTuple("workspace", "w2", "member", "u9")
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{keep}, nil); err != nil {
		t.Fatalf("seed tuple: %v", err)
	}
	if err := r.DeleteMembershipAndTuples(ctx(), p, "", "w2", "ghost", []authz.Tuple{keep}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("delete-missing err = %v, want ErrNotFound", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "workspace", "w2", "member"); len(subs) != 1 {
		t.Fatalf("tuple deleted despite membership-not-found rollback: %+v", subs)
	}
}
