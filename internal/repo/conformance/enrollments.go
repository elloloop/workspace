package conformance

import (
	"errors"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testEnrollments pins the enrollment lifecycle overlay identically across
// drivers: SetEnrollmentAndTuples moves the row and the backing group#member
// tuple together (present for access-bearing states, absent otherwise), the row
// survives a non-access transition, Get/List read back, and DeleteGroup cascades
// the enrollment rows.
func testEnrollments(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := r.CreateGroup(ctx(), grp(p, "cohort", "", now)); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	alice := service.GroupMember{UserID: "alice"}
	tup := userTuple("group", "cohort", "member", "alice")

	// Enroll active → row present AND the member tuple present.
	active := &service.Enrollment{
		ProjectID: p, GroupID: "cohort", Member: alice,
		State: service.EnrollmentActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.SetEnrollmentAndTuples(ctx(), active, []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("SetEnrollmentAndTuples active: %v", err)
	}
	if got, err := r.GetEnrollment(ctx(), p, "", "cohort", alice); err != nil || got.State != service.EnrollmentActive {
		t.Fatalf("GetEnrollment active = %+v, %v", got, err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "group", "cohort", "member"); len(subs) != 1 || subs[0].UserID != "alice" {
		t.Fatalf("active enrollee must be in the member set: %+v", subs)
	}

	// Transition to completed → tuple removed, but the row remains (now completed).
	completed := &service.Enrollment{
		ProjectID: p, GroupID: "cohort", Member: alice,
		State: service.EnrollmentCompleted, CreatedAt: now, UpdatedAt: now.Add(time.Hour),
	}
	if err := r.SetEnrollmentAndTuples(ctx(), completed, nil, []authz.Tuple{tup}); err != nil {
		t.Fatalf("SetEnrollmentAndTuples completed: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "group", "cohort", "member"); len(subs) != 0 {
		t.Fatalf("completed enrollee must NOT be in the member set: %+v", subs)
	}
	if got, err := r.GetEnrollment(ctx(), p, "", "cohort", alice); err != nil || got.State != service.EnrollmentCompleted {
		t.Fatalf("completed row must persist = %+v, %v", got, err)
	}

	// A second member, waitlisted (no tuple), so ListEnrollments has two rows.
	bob := service.GroupMember{UserID: "bob"}
	wl := &service.Enrollment{
		ProjectID: p, GroupID: "cohort", Member: bob,
		State: service.EnrollmentWaitlisted, CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second),
	}
	if err := r.SetEnrollmentAndTuples(ctx(), wl, nil, []authz.Tuple{userTuple("group", "cohort", "member", "bob")}); err != nil {
		t.Fatalf("SetEnrollmentAndTuples waitlisted: %v", err)
	}
	list, err := r.ListEnrollments(ctx(), p, "", "cohort")
	if err != nil || len(list) != 2 {
		t.Fatalf("ListEnrollments = %d, %v; want 2", len(list), err)
	}

	if _, err := r.GetEnrollment(ctx(), p, "", "cohort", service.GroupMember{UserID: "ghost"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("missing enrollment err = %v, want ErrNotFound", err)
	}

	// DeleteGroup cascades the enrollment rows.
	if err := r.DeleteGroup(ctx(), p, "", "cohort"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if list, _ := r.ListEnrollments(ctx(), p, "", "cohort"); len(list) != 0 {
		t.Fatalf("enrollments not cascaded on group delete: %d", len(list))
	}
}
