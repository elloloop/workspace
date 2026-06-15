// Package authz is a Zanzibar-style relation-tuple authorization engine.
//
// A relation tuple is `namespace:object#relation@subject`, where subject is
// a concrete user or a userset `namespace:object#relation`. A namespace
// model maps each relation to a userset-rewrite rule (union of: the stored
// tuples, a computed userset on the same object, or a tuple-to-userset that
// walks to a related object). Check evaluates a rule transitively; Expand
// returns the userset tree. The engine is generic — products register their
// own namespaces; the workspace/group/resource namespaces below are the
// built-in defaults that back this service's product surface.
package authz

// Subject is the right-hand side of a tuple: exactly one field is set.
type Subject struct {
	UserID string
	Set    *SubjectSet
}

// SubjectSet references the userset namespace:object#relation.
type SubjectSet struct {
	Namespace string
	ObjectID  string
	Relation  string
}

// Tuple is a full relation tuple `namespace:object#relation@subject`, used
// for stored writes. Reads go through TupleReader.ListSubjects.
type Tuple struct {
	Namespace string
	ObjectID  string
	Relation  string
	Subject   Subject
}

// Rewrite is a userset-rewrite expression for one relation.
type Rewrite struct {
	// Union holds the child rewrites; the relation grants access if ANY
	// child does. A zero Rewrite (all fields empty) means "this" — the
	// directly stored tuples for the relation.
	Union []Rewrite

	// Computed, when set, evaluates another relation on the SAME object.
	Computed string

	// TupleToUserset walks every subjectset stored under TuplesetRelation
	// on this object and checks ComputedRelation on each referenced object.
	TuplesetRelation string
	ComputedRelation string
}

// this is the leaf rewrite: evaluate the relation's own stored tuples.
func this() Rewrite { return Rewrite{} }

func union(rs ...Rewrite) Rewrite { return Rewrite{Union: rs} }

func computed(rel string) Rewrite { return Rewrite{Computed: rel} }

func tupleToUserset(tupleset, computedRel string) Rewrite {
	return Rewrite{TuplesetRelation: tupleset, ComputedRelation: computedRel}
}

func (r Rewrite) isThis() bool {
	return len(r.Union) == 0 && r.Computed == "" && r.TuplesetRelation == ""
}

// Namespace maps each relation name to its rewrite rule.
type Namespace map[string]Rewrite

// Model is the full set of namespace configurations.
type Model map[string]Namespace

// DefaultModel is the built-in authorization model.
//
//   - workspace: the membership grades, ordered owner ⊃ admin ⊃ member ⊃ guest.
//   - group:     a nestable membership set (subjects may be group usersets).
//   - resource:  a generic product object that inherits access from a parent
//     workspace (tuple_to_userset) and supports direct per-object sharing
//     (this) — covering Linear-style issues, learning-platform courses, and
//     a personal-assistant task shared with another person.
func DefaultModel() Model {
	return Model{
		"workspace": {
			"owner":  this(),
			"admin":  union(this(), computed("owner")),
			"member": union(this(), computed("admin")),
			"guest":  union(this(), computed("member")),
		},
		"group": {
			"member": this(),
		},
		"resource": {
			"parent": this(),
			"owner":  this(),
			"editor": union(this(), computed("owner"), tupleToUserset("parent", "admin")),
			"viewer": union(this(), computed("editor"), tupleToUserset("parent", "member")),
		},
	}
}

func (m Model) rewrite(namespace, relation string) Rewrite {
	if ns, ok := m[namespace]; ok {
		if rw, ok := ns[relation]; ok {
			return rw
		}
	}
	// Unknown relations default to direct tuples, so products can store
	// ad-hoc relations without first registering a namespace.
	return this()
}
