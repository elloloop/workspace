package conformance

import (
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testTupleExpiry pins time-bounded grants across every driver: an expired
// tuple is invisible to every read path, a future or absent expiry is visible,
// and re-writing a tuple replaces its expiry (expiry is metadata, not identity).
func testTupleExpiry(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	perm := userTuple("doc", "d1", "viewer", "u_perm") // never expires
	live := userTuple("doc", "d1", "viewer", "u_live")
	live.ExpiresAt = &future
	dead := userTuple("doc", "d1", "viewer", "u_dead")
	dead.ExpiresAt = &past
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{perm, live, dead}, nil); err != nil {
		t.Fatalf("WriteTuples: %v", err)
	}

	// ListSubjects filters the expired tuple; permanent + future survive.
	if got := subjectUsers(t, r, p, "doc", "d1", "viewer"); !got["u_perm"] || !got["u_live"] || got["u_dead"] {
		t.Fatalf("ListSubjects expiry filter = %v, want u_perm+u_live only", got)
	}
	// ReadTuples filters expired too.
	all, err := r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "doc", ObjectID: "d1"})
	if err != nil {
		t.Fatalf("ReadTuples: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ReadTuples = %d, want 2 (expired excluded)", len(all))
	}

	// Re-granting the expired tuple with a future expiry refreshes it (upsert).
	dead.ExpiresAt = &future
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{dead}, nil); err != nil {
		t.Fatalf("re-grant: %v", err)
	}
	if got := subjectUsers(t, r, p, "doc", "d1", "viewer"); !got["u_dead"] {
		t.Fatalf("upsert did not refresh expiry: %v", got)
	}

	// Re-granting a future tuple with no expiry makes it permanent.
	live.ExpiresAt = nil
	if err := r.WriteTuples(ctx(), p, "", []authz.Tuple{live}, nil); err != nil {
		t.Fatalf("re-grant permanent: %v", err)
	}
	all, _ = r.ReadTuples(ctx(), p, "", service.TupleFilter{Namespace: "doc", ObjectID: "d1"})
	for _, tp := range all {
		if tp.Subject.UserID == "u_live" && tp.ExpiresAt != nil {
			t.Fatalf("expected nil expiry after permanent re-grant, got %v", tp.ExpiresAt)
		}
	}
}

func subjectUsers(t *testing.T, r service.Repository, p, ns, obj, rel string) map[string]bool {
	t.Helper()
	subs, err := r.ListSubjects(ctx(), p, "", ns, obj, rel)
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	got := map[string]bool{}
	for _, s := range subs {
		got[s.UserID] = true
	}
	return got
}
