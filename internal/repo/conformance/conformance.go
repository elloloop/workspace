// Package conformance is a driver-agnostic test suite that pins every
// service.Repository implementation to the same contract: the in-memory
// reference driver and the Postgres driver must pass it identically.
package conformance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// Run executes the full conformance suite against repos produced by newRepo.
// newRepo must return a fresh, empty store on each call.
func Run(t *testing.T, newRepo func() service.Repository) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(*testing.T, service.Repository)
	}{
		{"Tuples", testTuples},
		{"WildcardTuples", testWildcardTuples},
		{"TupleExpiry", testTupleExpiry},
		{"Conditions", testConditions},
		{"WorkspaceCRUD", testWorkspaceCRUD},
		{"PersonalUniqueness", testPersonalUniqueness},
		{"DeleteWorkspaceCascade", testDeleteWorkspaceCascade},
		{"Memberships", testMemberships},
		{"WorkspacesForUser", testWorkspacesForUser},
		{"Invitations", testInvitations},
		{"Groups", testGroups},
		{"Enrollments", testEnrollments},
		{"ProjectIsolation", testProjectIsolation},
		{"TenantIsolation", testTenantIsolation},
		{"Projects", testProjects},
		{"Deprovision", testDeprovision},
		{"SubjectExport", testSubjectExport},
		{"AtomicMembership", testAtomicMembership},
		{"Seats", testSeats},
		{"NotFound", testNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, newRepo())
		})
	}
}

func ctx() context.Context { return context.Background() }

func userTuple(ns, obj, rel, user string) authz.Tuple {
	return authz.Tuple{Namespace: ns, ObjectID: obj, Relation: rel, Subject: authz.Subject{UserID: user}}
}

func setTuple(ns, obj, rel, sns, soid, srel string) authz.Tuple {
	return authz.Tuple{
		Namespace: ns, ObjectID: obj, Relation: rel,
		Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: sns, ObjectID: soid, Relation: srel}},
	}
}

func testTuples(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	tu := userTuple("workspace", "w1", "owner", "u1")
	ts := setTuple("workspace", "w1", "member", "group", "g1", "member")

	// Write two tuples.
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{tu, ts}, nil); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}
	// Idempotent insert.
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{tu}, nil); err != nil {
		t.Fatalf("WriteTuples idempotent: %v", err)
	}

	subs, err := r.ListSubjects(ctx(), p, "", "workspace", "w1", "owner")
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	if len(subs) != 1 || subs[0].UserID != "u1" {
		t.Fatalf("ListSubjects owner = %+v, want one u1", subs)
	}
	subs, _ = r.ListSubjects(ctx(), p, "", "workspace", "w1", "member")
	if len(subs) != 1 || subs[0].Set == nil || subs[0].Set.ObjectID != "g1" {
		t.Fatalf("ListSubjects member = %+v, want one set g1", subs)
	}

	// ReadTuples filtered by user.
	all, err := r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "workspace", ObjectID: "w1"})
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ReadTuples = %d, want 2", len(all))
	}
	byUser, _ := r.ReadTuples(ctx(), p, "", service.TupleFilter{SubjectUserID: "u1"})
	if len(byUser) != 1 {
		t.Fatalf("ReadTuples by user = %d, want 1", len(byUser))
	}

	// Delete one, delete-missing is a no-op.
	if err := r.WriteTuples(ctx(), p, "", nil, []authz.Tuple{tu, userTuple("workspace", "nope", "owner", "x")}); err != nil {
		t.Fatalf("WriteTuples delete: %v", err)
	}
	subs, _ = r.ListSubjects(ctx(), p, "", "workspace", "w1", "owner")
	if len(subs) != 0 {
		t.Fatalf("after delete owner subs = %d, want 0", len(subs))
	}
}

func ws(p, id, owner string, typ service.WorkspaceType, created time.Time) *service.Workspace {
	return &service.Workspace{
		ID: id, ProjectID: p, Slug: id, DisplayName: id, Type: typ,
		OwnerUserID: owner, CreatedAt: created, UpdatedAt: created,
	}
}

func testWorkspaceCRUD(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	w := ws(p, "w1", "u1", service.TypeTeam, now)
	if err := r.CreateWorkspace(ctx(), w); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if err := r.CreateWorkspace(ctx(), w); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("duplicate id err = %v, want ErrAlreadyExists", err)
	}

	got, err := r.GetWorkspace(ctx(), p, "", "w1")
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	if got.DisplayName != "w1" || got.Type != service.TypeTeam || !got.CreatedAt.Equal(now) {
		t.Fatalf("GetWorkspace = %+v", got)
	}

	got.DisplayName = "renamed"
	if err := r.UpdateWorkspace(ctx(), got); err != nil {
		t.Fatalf("UpdateWorkspace: %v", err)
	}
	got, _ = r.GetWorkspace(ctx(), p, "", "w1")
	if got.DisplayName != "renamed" {
		t.Fatalf("after update = %q", got.DisplayName)
	}

	if err := r.DeleteWorkspace(ctx(), p, "", "w1"); err != nil {
		t.Fatalf("DeleteWorkspace: %v", err)
	}
	if _, err := r.GetWorkspace(ctx(), p, "", "w1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("after delete get err = %v, want ErrNotFound", err)
	}
}

func testPersonalUniqueness(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC()
	if err := r.CreateWorkspace(ctx(), ws(p, "p1", "u1", service.TypePersonal, now)); err != nil {
		t.Fatalf("first personal: %v", err)
	}
	// Second personal for same owner → ErrAlreadyExists.
	if err := r.CreateWorkspace(ctx(), ws(p, "p2", "u1", service.TypePersonal, now)); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("second personal err = %v, want ErrAlreadyExists", err)
	}
	// Personal for a different owner is fine.
	if err := r.CreateWorkspace(ctx(), ws(p, "p3", "u2", service.TypePersonal, now)); err != nil {
		t.Fatalf("other owner personal: %v", err)
	}

	got, err := r.PersonalWorkspace(ctx(), p, "", "u1")
	if err != nil || got.ID != "p1" {
		t.Fatalf("PersonalWorkspace = %+v, %v", got, err)
	}
	if _, err := r.PersonalWorkspace(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("missing personal err = %v, want ErrNotFound", err)
	}
}

func testDeleteWorkspaceCascade(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC()
	if err := r.CreateWorkspace(ctx(), ws(p, "w1", "u1", service.TypeTeam, now)); err != nil {
		t.Fatalf("create: %v", err)
	}
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleOwner, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	if err := r.CreateInvitation(ctx(), inv(p, "i1", "w1", "tok1", now)); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{userTuple("workspace", "w1", "owner", "u1")}, nil); err != nil {
		t.Fatalf("tuple: %v", err)
	}

	if err := r.DeleteWorkspace(ctx(), p, "", "w1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := r.GetMembership(ctx(), p, "", "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("membership not cascaded: %v", err)
	}
	invs, _ := r.ListInvitations(ctx(), p, "", "w1")
	if len(invs) != 0 {
		t.Fatalf("invitations not cascaded: %d", len(invs))
	}
	subs, _ := r.ListSubjects(ctx(), p, "", "workspace", "w1", "owner")
	if len(subs) != 0 {
		t.Fatalf("tuples not cascaded: %d", len(subs))
	}
}

func mustPut(t *testing.T, r service.Repository, m *service.Membership) {
	t.Helper()
	if err := r.PutMembership(ctx(), m); err != nil {
		t.Fatalf("PutMembership: %v", err)
	}
}

func testMemberships(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleMember, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "w1", UserID: "u2",
		Role: service.RoleGuest, Status: service.StatusInvited, CreatedAt: now.Add(time.Second), UpdatedAt: now,
	})

	got, err := r.GetMembership(ctx(), p, "", "w1", "u1")
	if err != nil || got.Role != service.RoleMember {
		t.Fatalf("GetMembership = %+v, %v", got, err)
	}

	// Upsert overwrites.
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleAdmin, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	got, _ = r.GetMembership(ctx(), p, "", "w1", "u1")
	if got.Role != service.RoleAdmin {
		t.Fatalf("upsert role = %v", got.Role)
	}

	members, err := r.ListMembers(ctx(), p, "", "w1")
	if err != nil || len(members) != 2 {
		t.Fatalf("ListMembers = %d, %v", len(members), err)
	}
	if members[0].UserID != "u1" || members[1].UserID != "u2" {
		t.Fatalf("ListMembers order = %s,%s", members[0].UserID, members[1].UserID)
	}

	if err := r.DeleteMembership(ctx(), p, "", "w1", "u1"); err != nil {
		t.Fatalf("DeleteMembership: %v", err)
	}
	if _, err := r.GetMembership(ctx(), p, "", "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("after delete err = %v", err)
	}
	if err := r.DeleteMembership(ctx(), p, "", "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("delete missing err = %v, want ErrNotFound", err)
	}
}

func testWorkspacesForUser(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	base := time.Now().UTC().Truncate(time.Millisecond)
	// Create three workspaces with distinct CreatedAt.
	if err := r.CreateWorkspace(ctx(), ws(p, "wb", "x", service.TypeTeam, base.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateWorkspace(ctx(), ws(p, "wa", "x", service.TypeTeam, base.Add(1*time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateWorkspace(ctx(), ws(p, "wc", "x", service.TypeTeam, base.Add(3*time.Second))); err != nil {
		t.Fatal(err)
	}
	// u1 is active in wa, wb; invited (inactive) in wc.
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "wa", UserID: "u1",
		Role: service.RoleMember, Status: service.StatusActive, CreatedAt: base, UpdatedAt: base,
	})
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "wb", UserID: "u1",
		Role: service.RoleMember, Status: service.StatusActive, CreatedAt: base, UpdatedAt: base,
	})
	mustPut(t, r, &service.Membership{
		ProjectID: p, WorkspaceID: "wc", UserID: "u1",
		Role: service.RoleMember, Status: service.StatusInvited, CreatedAt: base, UpdatedAt: base,
	})

	got, err := r.WorkspacesForUser(ctx(), p, "", "u1")
	if err != nil {
		t.Fatalf("WorkspacesForUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("WorkspacesForUser = %d, want 2 (active only)", len(got))
	}
	// Ordered by CreatedAt: wa (1s) before wb (2s).
	if got[0].ID != "wa" || got[1].ID != "wb" {
		t.Fatalf("order = %s,%s, want wa,wb", got[0].ID, got[1].ID)
	}
}

func inv(p, id, wsID, tok string, now time.Time) *service.Invitation {
	return &service.Invitation{
		ID: id, ProjectID: p, WorkspaceID: wsID, Email: id + "@x.com",
		Role: service.RoleMember, Status: service.InvitePending, InvitedBy: "owner",
		TokenHash: tok, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func testInvitations(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := r.CreateInvitation(ctx(), inv(p, "i1", "w1", "tokA", now)); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if err := r.CreateInvitation(ctx(), inv(p, "i2", "w1", "tokB", now.Add(time.Second))); err != nil {
		t.Fatalf("CreateInvitation i2: %v", err)
	}
	if err := r.CreateInvitation(ctx(), inv(p, "i1", "w1", "dup", now)); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("dup id err = %v, want ErrAlreadyExists", err)
	}

	got, err := r.GetInvitation(ctx(), p, "", "i1")
	if err != nil || got.TokenHash != "tokA" {
		t.Fatalf("GetInvitation = %+v, %v", got, err)
	}
	got, err = r.GetInvitationByTokenHash(ctx(), p, "", "tokB")
	if err != nil || got.ID != "i2" {
		t.Fatalf("GetInvitationByTokenHash = %+v, %v", got, err)
	}

	got.Status = service.InviteAccepted
	if err := r.UpdateInvitation(ctx(), got); err != nil {
		t.Fatalf("UpdateInvitation: %v", err)
	}
	got, _ = r.GetInvitation(ctx(), p, "", "i2")
	if got.Status != service.InviteAccepted {
		t.Fatalf("after update status = %v", got.Status)
	}

	list, err := r.ListInvitations(ctx(), p, "", "w1")
	if err != nil || len(list) != 2 {
		t.Fatalf("ListInvitations = %d, %v", len(list), err)
	}
	if list[0].ID != "i1" || list[1].ID != "i2" {
		t.Fatalf("ListInvitations order = %s,%s", list[0].ID, list[1].ID)
	}
}

func grp(p, id, wsID string, now time.Time) *service.Group {
	return &service.Group{
		ID: id, ProjectID: p, WorkspaceID: wsID, Slug: id, DisplayName: id,
		CreatedBy: "u1", CreatedAt: now, UpdatedAt: now,
	}
}

func testGroups(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := r.CreateGroup(ctx(), grp(p, "g1", "w1", now)); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := r.CreateGroup(ctx(), grp(p, "g2", "w2", now.Add(time.Second))); err != nil {
		t.Fatalf("CreateGroup g2: %v", err)
	}
	if err := r.CreateGroup(ctx(), grp(p, "g3", "", now.Add(2*time.Second))); err != nil {
		t.Fatalf("CreateGroup standalone: %v", err)
	}
	if err := r.CreateGroup(ctx(), grp(p, "g1", "w1", now)); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("dup group err = %v, want ErrAlreadyExists", err)
	}

	got, err := r.GetGroup(ctx(), p, "", "g1")
	if err != nil || got.WorkspaceID != "w1" {
		t.Fatalf("GetGroup = %+v, %v", got, err)
	}

	all, err := r.ListGroups(ctx(), p, "", "")
	if err != nil || len(all) != 3 {
		t.Fatalf("ListGroups all = %d, %v", len(all), err)
	}
	scoped, _ := r.ListGroups(ctx(), p, "", "w1")
	if len(scoped) != 1 || scoped[0].ID != "g1" {
		t.Fatalf("ListGroups w1 = %+v", scoped)
	}

	// Group tuple should cascade on delete.
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{userTuple("group", "g1", "member", "u1")}, nil); err != nil {
		t.Fatalf("group tuple: %v", err)
	}
	if err := r.DeleteGroup(ctx(), p, "", "g1"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := r.GetGroup(ctx(), p, "", "g1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("after delete err = %v", err)
	}
	subs, _ := r.ListSubjects(ctx(), p, "", "group", "g1", "member")
	if len(subs) != 0 {
		t.Fatalf("group tuples not cascaded: %d", len(subs))
	}
}

func testProjectIsolation(t *testing.T, r service.Repository) {
	t.Helper()
	const a, b = "projA", "projB"
	now := time.Now().UTC()
	if err := r.CreateWorkspace(ctx(), ws(a, "w1", "u1", service.TypeTeam, now)); err != nil {
		t.Fatal(err)
	}
	mustPut(t, r, &service.Membership{
		ProjectID: a, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleOwner, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	if err := r.CreateGroup(ctx(), grp(a, "g1", "w1", now)); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateInvitation(ctx(), inv(a, "i1", "w1", "tok", now)); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteTuples(ctx(), a, "", []authz.Tuple{userTuple("workspace", "w1", "owner", "u1")}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.SetEnrollmentAndTuples(ctx(), &service.Enrollment{
		ProjectID: a, GroupID: "g1", Member: service.GroupMember{UserID: "u1"},
		State: service.EnrollmentActive, CreatedAt: now, UpdatedAt: now,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}

	// None of project A's data is visible under project B.
	if _, err := r.GetWorkspace(ctx(), b, "", "w1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("workspace leaked: %v", err)
	}
	if _, err := r.GetGroup(ctx(), b, "", "g1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("group leaked: %v", err)
	}
	if _, err := r.GetInvitation(ctx(), b, "", "i1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("invitation leaked: %v", err)
	}
	if _, err := r.GetMembership(ctx(), b, "", "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("membership leaked: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), b, "", "workspace", "w1", "owner"); len(subs) != 0 {
		t.Fatalf("tuple leaked: %d", len(subs))
	}
	if wss, _ := r.WorkspacesForUser(ctx(), b, "", "u1"); len(wss) != 0 {
		t.Fatalf("WorkspacesForUser leaked: %d", len(wss))
	}
	if _, err := r.GetEnrollment(ctx(), b, "", "g1", service.GroupMember{UserID: "u1"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("enrollment leaked across project: %v", err)
	}

	// Same id can be reused independently in project B.
	if err := r.CreateWorkspace(ctx(), ws(b, "w1", "u9", service.TypeTeam, now)); err != nil {
		t.Fatalf("reuse id under B: %v", err)
	}
}

func testNotFound(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	if _, err := r.GetWorkspace(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetWorkspace = %v", err)
	}
	if err := r.UpdateWorkspace(ctx(), ws(p, "ghost", "u", service.TypeTeam, time.Now())); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("UpdateWorkspace = %v", err)
	}
	if err := r.DeleteWorkspace(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("DeleteWorkspace = %v", err)
	}
	if _, err := r.GetMembership(ctx(), p, "", "w", "u"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetMembership = %v", err)
	}
	if _, err := r.GetInvitation(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetInvitation = %v", err)
	}
	if _, err := r.GetInvitationByTokenHash(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetInvitationByTokenHash = %v", err)
	}
	if err := r.UpdateInvitation(ctx(), inv(p, "ghost", "w", "t", time.Now())); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("UpdateInvitation = %v", err)
	}
	if _, err := r.GetGroup(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetGroup = %v", err)
	}
	if err := r.DeleteGroup(ctx(), p, "", "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("DeleteGroup = %v", err)
	}
}

// testTenantIsolation pins that two tenants within one project never see each
// other's data, and that ids are reusable across tenants — the same guarantee
// as project isolation, one shard level down.
func testTenantIsolation(t *testing.T, r service.Repository) {
	t.Helper()
	const p, t1, t2 = "proj", "tenantA", "tenantB"
	now := time.Now().UTC()

	w := &service.Workspace{
		ID: "w1", ProjectID: p, TenantID: t1, Slug: "w1", DisplayName: "w1",
		Type: service.TypeTeam, OwnerUserID: "u1", CreatedAt: now, UpdatedAt: now,
	}
	if err := r.CreateWorkspace(ctx(), w); err != nil {
		t.Fatalf("create: %v", err)
	}
	mustPut(t, r, &service.Membership{
		ProjectID: p, TenantID: t1, WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleOwner, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	})
	if err := r.CreateGroup(ctx(), &service.Group{
		ID: "g1", ProjectID: p, TenantID: t1, Slug: "g1", DisplayName: "g1", CreatedBy: "u1", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("group: %v", err)
	}
	if err := r.WriteTuples(ctx(), p, t1, []authz.Tuple{userTuple("workspace", "w1", "owner", "u1")}, nil); err != nil {
		t.Fatalf("tuple: %v", err)
	}
	if err := r.SetEnrollmentAndTuples(ctx(), &service.Enrollment{
		ProjectID: p, TenantID: t1, GroupID: "g1", Member: service.GroupMember{UserID: "u1"},
		State: service.EnrollmentActive, CreatedAt: now, UpdatedAt: now,
	}, nil, nil); err != nil {
		t.Fatalf("enrollment: %v", err)
	}

	// None of tenant A's data is visible under tenant B of the same project.
	if _, err := r.GetWorkspace(ctx(), p, t2, "w1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("workspace leaked across tenant: %v", err)
	}
	if _, err := r.GetGroup(ctx(), p, t2, "g1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("group leaked across tenant: %v", err)
	}
	if _, err := r.GetMembership(ctx(), p, t2, "w1", "u1"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("membership leaked across tenant: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, t2, "workspace", "w1", "owner"); len(subs) != 0 {
		t.Fatalf("tuple leaked across tenant: %d", len(subs))
	}
	if wss, _ := r.WorkspacesForUser(ctx(), p, t2, "u1"); len(wss) != 0 {
		t.Fatalf("WorkspacesForUser leaked across tenant: %d", len(wss))
	}
	if _, err := r.GetEnrollment(ctx(), p, t2, "g1", service.GroupMember{UserID: "u1"}); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("enrollment leaked across tenant: %v", err)
	}
	if es, _ := r.ListEnrollments(ctx(), p, t2, "g1"); len(es) != 0 {
		t.Fatalf("ListEnrollments leaked across tenant: %d", len(es))
	}

	// The same id is reusable in another tenant.
	if err := r.CreateWorkspace(ctx(), &service.Workspace{
		ID: "w1", ProjectID: p, TenantID: t2, Slug: "w1", DisplayName: "w1",
		Type: service.TypeTeam, OwnerUserID: "u9", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("reuse id under tenant B: %v", err)
	}
}

// testProjects pins the project configuration store: CRUD, model round-trip,
// duplicate/not-found semantics, and that a model-less project reads back nil.
func testProjects(t *testing.T, r service.Repository) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	model, err := authz.ParseModel([]byte(`{"course":{"viewer":{"this":true},"editor":{"union":[{"this":true},{"computed":"viewer"}]}}}`))
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}

	p1 := &service.Project{ID: "prj1", Name: "Kids", Status: service.ProjectActive, Model: model, CreatedAt: now, UpdatedAt: now}
	if err := r.CreateProject(ctx(), p1); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if err := r.CreateProject(ctx(), p1); !errors.Is(err, service.ErrAlreadyExists) {
		t.Fatalf("duplicate project err = %v, want ErrAlreadyExists", err)
	}
	// Model-less project falls back to nil (the default model).
	if err := r.CreateProject(ctx(), &service.Project{ID: "prj2", Name: "Pro", Status: service.ProjectActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateProject prj2: %v", err)
	}

	got, err := r.GetProject(ctx(), "prj1")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	gotJSON, _ := authz.MarshalModel(got.Model)
	wantJSON, _ := authz.MarshalModel(model)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("model round-trip:\n got %s\nwant %s", gotJSON, wantJSON)
	}
	if got2, _ := r.GetProject(ctx(), "prj2"); got2.Model != nil {
		t.Fatalf("prj2 model = %v, want nil", got2.Model)
	}

	list, err := r.ListProjects(ctx())
	if err != nil || len(list) != 2 {
		t.Fatalf("ListProjects = %d, %v", len(list), err)
	}

	got.Status = service.ProjectSuspended
	got.Model = nil
	if err := r.UpdateProject(ctx(), got); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if after, _ := r.GetProject(ctx(), "prj1"); after.Status != service.ProjectSuspended || after.Model != nil {
		t.Fatalf("after update = %+v", after)
	}

	if _, err := r.GetProject(ctx(), "ghost"); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("GetProject ghost = %v", err)
	}
}

// testDeprovision pins that DeleteAllSubjectTuplesInProject removes every tuple
// whose concrete subject is the user across all namespaces AND ALL TENANTS of
// the project, while leaving other subjects and other projects untouched.
func testDeprovision(t *testing.T, r service.Repository) {
	t.Helper()
	const p, other = "proj", "proj2"
	// u1 holds grants in two tenants of p, plus an unrelated subject u2; u1 also
	// holds a grant in a DIFFERENT project that must survive the erase.
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{
		userTuple("workspace", "w1", "owner", "u1"),
		userTuple("group", "g1", "member", "u1"),
		userTuple("resource", "doc2", "viewer", "u2"),
	}, nil); err != nil {
		t.Fatalf("WriteTuples tenant '': %v", err)
	}
	if err := r.WriteTuples(ctx(), p, "t2", []authz.Tuple{
		userTuple("resource", "doc1", "viewer", "u1"),
	}, nil); err != nil {
		t.Fatalf("WriteTuples tenant t2: %v", err)
	}
	if err := r.WriteTuples(ctx(), other, "", []authz.Tuple{
		userTuple("resource", "doc9", "viewer", "u1"),
	}, nil); err != nil {
		t.Fatalf("WriteTuples other project: %v", err)
	}

	n, err := r.DeleteAllSubjectTuplesInProject(ctx(), p, "u1")
	if err != nil {
		t.Fatalf("DeleteAllSubjectTuplesInProject: %v", err)
	}
	if n != 3 { // owner+member in tenant '', viewer in tenant t2
		t.Fatalf("deleted = %d, want 3 (across both tenants)", n)
	}
	// u1 is erased in BOTH tenants of p.
	if subs, _ := r.ListSubjects(ctx(), p, "", "workspace", "w1", "owner"); len(subs) != 0 {
		t.Fatalf("u1 tenant '' not erased: %d", len(subs))
	}
	if subs, _ := r.ListSubjects(ctx(), p, "t2", "resource", "doc1", "viewer"); len(subs) != 0 {
		t.Fatalf("u1 tenant t2 not erased (cross-tenant leak): %d", len(subs))
	}
	// u2 (same project) and u1's grant in another project both survive.
	if subs, _ := r.ListSubjects(ctx(), p, "", "resource", "doc2", "viewer"); len(subs) != 1 {
		t.Fatalf("u2 grant should survive, got %d", len(subs))
	}
	if subs, _ := r.ListSubjects(ctx(), other, "", "resource", "doc9", "viewer"); len(subs) != 1 {
		t.Fatalf("u1 grant in other project must survive, got %d", len(subs))
	}
}
