package tests

import (
	"context"
	"testing"

	"connectrpc.com/connect"

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

// TestEnrollmentRequiresGroupManager: the enrollment RPCs are gated — a
// non-manager calling SetEnrollmentState/ListEnrollments on someone else's
// cohort is denied.
func TestEnrollmentRequiresGroupManager(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{
		ActingUserId: "alice", DisplayName: "Cohort 8",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	cohort := created.Msg.Group.Id

	// mallory is not the group's manager.
	_, err = h.grp.SetEnrollmentState(ctx, req(&workspacev1.SetEnrollmentStateRequest{
		ActingUserId: "mallory", GroupId: cohort,
		Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: "bob"}},
		State:  workspacev1.EnrollmentState_ENROLLMENT_STATE_ACTIVE,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-manager SetEnrollmentState: want PermissionDenied, got %v", err)
	}
	_, err = h.grp.ListEnrollments(ctx, req(&workspacev1.ListEnrollmentsRequest{
		ActingUserId: "mallory", GroupId: cohort,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-manager ListEnrollments: want PermissionDenied, got %v", err)
	}
}

// TestEnrollmentAndMembershipStayConsistent: interleaving the plain
// AddGroupMember/RemoveGroupMember path with the enrollment overlay keeps the
// roster (ListEnrollments) consistent with actual access (the group#member
// tuple) — a tracked member cannot end up "active" on the roster with no access,
// or accessible with a "dropped" roster entry.
func TestEnrollmentAndMembershipStayConsistent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.grp.CreateGroup(ctx, req(&workspacev1.CreateGroupRequest{
		ActingUserId: "alice", DisplayName: "Cohort 9",
	}))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	cohort := created.Msg.Group.Id

	// In the group's #member set?
	inSet := func(user string) bool {
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			Namespace: "group", ObjectId: cohort, Relation: "member", SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s: %v", user, err)
		}
		return got.Msg.Allowed
	}
	rosterState := func(user string) workspacev1.EnrollmentState {
		list, err := h.grp.ListEnrollments(ctx, req(&workspacev1.ListEnrollmentsRequest{ActingUserId: "alice", GroupId: cohort}))
		if err != nil {
			t.Fatalf("ListEnrollments: %v", err)
		}
		for _, e := range list.Msg.Enrollments {
			if e.Member.GetUserId() == user {
				return e.State
			}
		}
		return workspacev1.EnrollmentState_ENROLLMENT_STATE_UNSPECIFIED
	}
	setEnroll := func(user string, st workspacev1.EnrollmentState) {
		if _, err := h.grp.SetEnrollmentState(ctx, req(&workspacev1.SetEnrollmentStateRequest{
			ActingUserId: "alice", GroupId: cohort,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: user}}, State: st,
		})); err != nil {
			t.Fatalf("SetEnrollmentState %s: %v", user, err)
		}
	}
	addMember := func(user string) {
		if _, err := h.grp.AddGroupMember(ctx, req(&workspacev1.AddGroupMemberRequest{
			ActingUserId: "alice", GroupId: cohort,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: user}},
		})); err != nil {
			t.Fatalf("AddGroupMember %s: %v", user, err)
		}
	}
	removeMember := func(user string) {
		if _, err := h.grp.RemoveGroupMember(ctx, req(&workspacev1.RemoveGroupMemberRequest{
			ActingUserId: "alice", GroupId: cohort,
			Member: &workspacev1.GroupMember{Member: &workspacev1.GroupMember_UserId{UserId: user}},
		})); err != nil {
			t.Fatalf("RemoveGroupMember %s: %v", user, err)
		}
	}

	// Enroll bob active, then RemoveGroupMember him: access ends AND the roster
	// reflects it (Dropped, not a stale "active").
	setEnroll("bob", workspacev1.EnrollmentState_ENROLLMENT_STATE_ACTIVE)
	if !inSet("bob") {
		t.Fatal("active bob should be in the member set")
	}
	removeMember("bob")
	if inSet("bob") {
		t.Fatal("removed bob must lose access")
	}
	if rosterState("bob") != workspacev1.EnrollmentState_ENROLLMENT_STATE_DROPPED {
		t.Fatalf("removed tracked member must show DROPPED, got %v", rosterState("bob"))
	}

	// carol dropped, then AddGroupMember her back: access turns on AND the roster
	// reflects it (Enrolled, not a stale "dropped").
	setEnroll("carol", workspacev1.EnrollmentState_ENROLLMENT_STATE_DROPPED)
	if inSet("carol") {
		t.Fatal("dropped carol should not have access")
	}
	addMember("carol")
	if !inSet("carol") {
		t.Fatal("re-added carol must gain access")
	}
	if rosterState("carol") != workspacev1.EnrollmentState_ENROLLMENT_STATE_ENROLLED {
		t.Fatalf("re-added tracked member must show ENROLLED, got %v", rosterState("carol"))
	}
}
