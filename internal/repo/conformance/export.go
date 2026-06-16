package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testSubjectExport pins the read primitives behind subject grant export:
// ListSubjectTuplesInProject returns a user's direct tuples across every tenant
// of the project (excluding other users and other projects), and
// ListTuplesForSubjectSetsInProject returns the grants held by a userset.
func testSubjectExport(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	must := func(tenant string, ts ...authz.Tuple) {
		t.Helper()
		if err := r.WriteTuples(ctx(), p, tenant, ts, nil); err != nil {
			t.Fatalf("WriteTuples: %v", err)
		}
	}
	// Direct grants for "u" across two tenants, including a group membership.
	must("t1", userTuple("workspace", "w1", "admin", "u"), userTuple("group", "g1", "member", "u"))
	must("t2", userTuple("resource", "doc1", "viewer", "u"))
	// A grant held BY the group g1 (group-mediated).
	must("t1", setTuple("resource", "proj1", "editor", "group", "g1", "member"))
	// Noise: another user (same project) and the same user in another project.
	must("t1", userTuple("workspace", "w1", "admin", "other"))
	if err := r.WriteTuples(ctx(), "otherproj", "t1", []authz.Tuple{userTuple("workspace", "w9", "owner", "u")}, nil); err != nil {
		t.Fatalf("WriteTuples otherproj: %v", err)
	}

	direct, err := r.ListSubjectTuplesInProject(ctx(), p, "u")
	if err != nil {
		t.Fatalf("ListSubjectTuplesInProject: %v", err)
	}
	if len(direct) != 3 {
		t.Fatalf("direct = %d, want 3 (excludes other user + other project): %+v", len(direct), direct)
	}
	tenants := map[string]bool{}
	groupID := ""
	for _, ta := range direct {
		if ta.Tuple.Subject.UserID != "u" {
			t.Fatalf("non-u subject leaked: %+v", ta)
		}
		tenants[ta.TenantID] = true
		if ta.Tuple.Namespace == "group" && ta.Tuple.Relation == "member" {
			groupID = ta.Tuple.ObjectID
		}
	}
	if !tenants["t1"] || !tenants["t2"] {
		t.Fatalf("tenant coverage = %v, want t1+t2", tenants)
	}
	if groupID != "g1" {
		t.Fatalf("group membership not surfaced, got %q", groupID)
	}

	via, err := r.ListTuplesForSubjectSetsInProject(ctx(), p,
		[]authz.SubjectSet{{Namespace: "group", ObjectID: "g1", Relation: "member"}})
	if err != nil {
		t.Fatalf("ListTuplesForSubjectSetsInProject: %v", err)
	}
	if len(via) != 1 || via[0].Tuple.ObjectID != "proj1" || via[0].TenantID != "t1" {
		t.Fatalf("via-group = %+v, want one resource:proj1 in t1", via)
	}
}
