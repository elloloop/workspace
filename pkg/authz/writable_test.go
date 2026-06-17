package authz

import "testing"

// TestWritableRelation pins which relations accept a directly-stored tuple: a
// relation is writable iff its rewrite reaches a `this` leg through the
// same-relation operators (union/intersection/exclusion), NOT through computed
// or tuple_to_userset (which evaluate a different relation/object).
func TestWritableRelation(t *testing.T) {
	m := DefaultModel()
	cases := []struct {
		ns, rel string
		want    bool
	}{
		// workspace: grades reach `this` (directly or via union) → writable.
		{"workspace", "owner", true},
		{"workspace", "admin", true},  // union(this, computed)
		{"workspace", "member", true}, // union(this, computed)
		{"workspace", "guest", true},
		// workspace editor/viewer are pure computed aliases → NOT writable.
		{"workspace", "editor", false}, // computed("admin")
		{"workspace", "viewer", false}, // computed("member")
		// group member is `this` → writable.
		{"group", "member", true},
		// resource viewer/editor are union(this, ...) → writable despite the
		// computed/tuple_to_userset legs.
		{"resource", "owner", true},
		{"resource", "parent", true},
		{"resource", "editor", true},
		{"resource", "viewer", true},
		// Unknown namespace / relation default to `this` → writable.
		{"doc", "viewer", true},
		{"workspace", "nonexistent", true},
	}
	for _, c := range cases {
		if got := m.WritableRelation(c.ns, c.rel); got != c.want {
			t.Errorf("WritableRelation(%q,%q) = %v, want %v", c.ns, c.rel, got, c.want)
		}
	}
}

// TestReadsStoredTuplesOperators pins the per-operator rule directly, including
// nesting and the both-sides-of-exclusion case.
func TestReadsStoredTuplesOperators(t *testing.T) {
	cases := []struct {
		name string
		rw   Rewrite
		want bool
	}{
		{"this", this(), true},
		{"computed-only", computed("admin"), false},
		{"tuple_to_userset-only", tupleToUserset("parent", "viewer"), false},
		{"union with this", union(this(), computed("admin")), true},
		{"union without this", union(computed("a"), tupleToUserset("parent", "b")), false},
		{"intersection with this", intersection(this(), computed("admin")), true},
		{"intersection without this", intersection(computed("a"), computed("b")), false},
		{"exclusion include-this", exclusion(this(), computed("banned")), true},
		{"exclusion exclude-this", exclusion(computed("member"), this()), true},
		{"exclusion neither this", exclusion(computed("member"), computed("banned")), false},
		{"nested union-in-intersection with this", intersection(union(this(), computed("x")), computed("y")), true},
	}
	for _, c := range cases {
		if got := c.rw.readsStoredTuples(); got != c.want {
			t.Errorf("%s: readsStoredTuples = %v, want %v", c.name, got, c.want)
		}
	}
}
