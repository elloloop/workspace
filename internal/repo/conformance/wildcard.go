package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testWildcardTuples pins the public-wildcard (user:*) subject across every
// driver: it must round-trip through ListSubjects as a wildcard (not an empty
// user), and DeleteAllSubjectTuples must remove a user's concrete grants while
// leaving a wildcard grant intact (deprovision must not over-delete public
// content).
func testWildcardTuples(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	wild := authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "viewer", Subject: authz.Subject{Wildcard: true}}
	bob := userTuple("doc", "d1", "viewer", "bob")
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{wild, bob}, nil); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}

	subs, err := r.ListSubjects(ctx(), p, "", "doc", "d1", "viewer")
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	var wildcards, users int
	for _, s := range subs {
		switch {
		case s.Wildcard:
			if s.Set != nil || s.UserID != "" {
				t.Fatalf("wildcard subject must have no user/set: %+v", s)
			}
			wildcards++
		case s.UserID == "bob":
			users++
		default:
			t.Fatalf("unexpected subject %+v", s)
		}
	}
	if wildcards != 1 || users != 1 {
		t.Fatalf("ListSubjects = %d wildcards, %d users; want 1 each", wildcards, users)
	}

	// Deprovisioning bob removes his concrete grant but leaves the wildcard.
	if _, err := r.DeleteAllSubjectTuples(ctx(), p, "", "bob"); err != nil {
		t.Fatalf("DeleteAllSubjectTuples: %v", err)
	}
	subs, _ = r.ListSubjects(ctx(), p, "", "doc", "d1", "viewer")
	if len(subs) != 1 || !subs[0].Wildcard {
		t.Fatalf("after deprovision = %+v, want only the wildcard grant", subs)
	}
}
