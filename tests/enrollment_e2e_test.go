package tests

import (
	"context"
	"testing"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestEnrollmentLifecycleOverAPI: a cohort group is granted viewer on a course
// resource via its `#member` userset; a learner's access then follows their
// enrollment state — present for active/enrolled, absent for completed/dropped/
// waitlisted — purely by the group#member tuple moving, end to end.
func TestEnrollmentLifecycleOverAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// alice creates the cohort group (she is its manager).
	created, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{
		ActingUserId: "alice", DisplayName: "Cohort 7",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	cohort := created.Msg.Group.Id

	// Grant the cohort viewer on course:c1 via the group userset.
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: "c1", Relation: "viewer",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "group", ObjectId: cohort, Relation: "member",
				}}},
			},
		}},
	})); err != nil {
		t.Fatalf("grant cohort viewer: %v", err)
	}

	canView := func(user string) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "c1", Relation: "viewer", SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s: %v", user, err)
		}
		return got.Msg.Allowed
	}
	enroll := func(user string, state workspacev1.EnrollmentState) {
		if _, err := h.grp.SetEnrollmentState(ctx, req(&workspacev1.SetEnrollmentStateRequest{
			ActingUserId: "alice", GroupId: cohort,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: user}},
			State:  state,
		})); err != nil {
			t.Fatalf("SetEnrollmentState %s=%v: %v", user, state, err)
		}
	}

	enroll("bob", workspacev1.EnrollmentState_ENROLLMENT_STATE_ACTIVE)
	if !canView("bob") {
		t.Fatal("an ACTIVE enrollee must inherit the cohort's viewer grant")
	}
	enroll("carol", workspacev1.EnrollmentState_ENROLLMENT_STATE_WAITLISTED)
	if canView("carol") {
		t.Fatal("a WAITLISTED enrollee must NOT have access")
	}

	// bob completes the course → access ends (tuple absence), but the row stays.
	enroll("bob", workspacev1.EnrollmentState_ENROLLMENT_STATE_COMPLETED)
	if canView("bob") {
		t.Fatal("a COMPLETED enrollee must lose access")
	}

	// carol is admitted off the waitlist → access turns on.
	enroll("carol", workspacev1.EnrollmentState_ENROLLMENT_STATE_ENROLLED)
	if !canView("carol") {
		t.Fatal("an ENROLLED enrollee must gain access")
	}

	// ListEnrollments shows both, with their final states.
	list, err := h.grp.ListEnrollments(ctx, req(&workspacev1.ListEnrollmentsRequest{
		ActingUserId: "alice", GroupId: cohort,
	}))
	if err != nil {
		t.Fatalf("ListEnrollments: %v", err)
	}
	states := map[string]workspacev1.EnrollmentState{}
	for _, e := range list.Msg.Enrollments {
		states[e.Member.GetUserId()] = e.State
	}
	if states["bob"] != workspacev1.EnrollmentState_ENROLLMENT_STATE_COMPLETED {
		t.Fatalf("bob state = %v, want COMPLETED", states["bob"])
	}
	if states["carol"] != workspacev1.EnrollmentState_ENROLLMENT_STATE_ENROLLED {
		t.Fatalf("carol state = %v, want ENROLLED", states["carol"])
	}
}
