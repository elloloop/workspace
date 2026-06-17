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

import (
	"context"
	"time"
)

// Subject is the right-hand side of a tuple: exactly one of UserID, Set, or
// Wildcard is set. Wildcard is the public "everyone" subject (Zanzibar's
// `user:*`): a stored wildcard tuple grants the relation to ANY user, which
// backs link-sharing and published/public content.
type Subject struct {
	UserID   string
	Set      *SubjectSet
	Wildcard bool
	// Condition, when non-nil, makes this grant conditional: the subject is
	// granted the relation only if the named condition evaluates true against
	// the request-time context (see conditions.go). Nil = unconditional (the
	// default). It is grant metadata, not part of tuple identity.
	Condition *Condition
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
	// ExpiresAt, when non-nil, time-bounds the grant: the tuple is inert once
	// the instant passes. Nil = permanent. It is metadata, not identity — two
	// tuples that differ only in ExpiresAt are the same tuple.
	ExpiresAt *time.Time
}

// ActiveAt reports whether the tuple grants at instant now: a nil expiry is
// always active, otherwise the expiry must be strictly in the future. Stores
// use this to filter expired tuples out of every read path.
func (t Tuple) ActiveAt(now time.Time) bool {
	return t.ExpiresAt == nil || t.ExpiresAt.After(now)
}

// Rewrite is a userset-rewrite expression for one relation.
type Rewrite struct {
	// Union holds the child rewrites; the relation grants access if ANY
	// child does. A zero Rewrite (all fields empty) means "this" — the
	// directly stored tuples for the relation.
	Union []Rewrite

	// Intersection holds child rewrites; the relation grants access only if
	// EVERY child does (Zanzibar's intersection). An empty slice is ignored.
	Intersection []Rewrite

	// Exclusion, when set, grants access if Include grants it AND Exclude
	// does NOT (Zanzibar's difference / "A but not B"). This is what lets a
	// suspended/blocked subject be denied without mutating their base grant,
	// e.g. active_member = member AND NOT suspended.
	Exclusion *Exclusion

	// Computed, when set, evaluates another relation on the SAME object.
	Computed string

	// TupleToUserset walks every subjectset stored under TuplesetRelation
	// on this object and checks ComputedRelation on each referenced object.
	TuplesetRelation string
	ComputedRelation string
}

// Exclusion is the difference rewrite: Include minus Exclude.
type Exclusion struct {
	Include Rewrite
	Exclude Rewrite
}

// this is the leaf rewrite: evaluate the relation's own stored tuples.
func this() Rewrite { return Rewrite{} }

func union(rs ...Rewrite) Rewrite { return Rewrite{Union: rs} }

func intersection(rs ...Rewrite) Rewrite { return Rewrite{Intersection: rs} }

func exclusion(include, exclude Rewrite) Rewrite {
	return Rewrite{Exclusion: &Exclusion{Include: include, Exclude: exclude}}
}

func computed(rel string) Rewrite { return Rewrite{Computed: rel} }

func tupleToUserset(tupleset, computedRel string) Rewrite {
	return Rewrite{TuplesetRelation: tupleset, ComputedRelation: computedRel}
}

func (r Rewrite) isThis() bool {
	return len(r.Union) == 0 && len(r.Intersection) == 0 && r.Exclusion == nil &&
		r.Computed == "" && r.TuplesetRelation == ""
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
//     (a workspace OR another resource, for nested folders/collections) and
//     supports direct per-object sharing (this) — covering Linear-style issues,
//     learning-platform courses, and a personal-assistant task shared with
//     another person.
func DefaultModel() Model {
	return Model{
		// workspace: the grades owner ⊃ admin ⊃ member ⊃ guest, plus editor/viewer
		// aliases (editor=admin, viewer=member) so a resource inherits from a
		// workspace parent through a SINGLE editor/viewer leg. The aliases resolve
		// through the model (computed), NOT raw tuples, so a stray
		// `workspace:w#editor@x` tuple is inert and cannot leak onto child resources.
		"workspace": {
			"owner":  this(),
			"admin":  union(this(), computed("owner")),
			"member": union(this(), computed("admin")),
			"guest":  union(this(), computed("member")),
			"editor": computed("admin"),
			"viewer": computed("member"),
		},
		"group": {
			"member": this(),
		},
		// resource: a generic product object that inherits access from its
		// `parent`, which may be a workspace OR another resource (nested
		// folders/collections). editor/viewer flow transitively up the chain via a
		// SINGLE parent leg per level: a WORKSPACE parent resolves editor→admin /
		// viewer→member through the workspace aliases above; a RESOURCE parent
		// recurses editor/viewer up the chain. A workspace-rooted resource behaves
		// exactly as before. Deep chains are bounded by the engine's maxDepth and
		// made cheap by request-scoped memoization.
		"resource": {
			"parent": this(),
			"owner":  this(),
			"editor": union(this(), computed("owner"), tupleToUserset("parent", "editor")),
			"viewer": union(this(), computed("editor"), tupleToUserset("parent", "viewer")),
		},
	}
}

// ModelResolver returns the authorization model for a project. It lets each
// project carry its own namespaces/relations (configured out of band) while
// the engine stays generic. Implementations MUST fall back to DefaultModel
// for projects with no configured model, so an unconfigured project behaves
// exactly like the built-in defaults.
type ModelResolver interface {
	ModelFor(ctx context.Context, projectID string) (Model, error)
}

// StaticResolver returns the same model for every project. A nil/empty model
// falls back to DefaultModel, so StaticResolver(nil) is the built-in default.
func StaticResolver(m Model) ModelResolver {
	if len(m) == 0 {
		m = DefaultModel()
	}
	return staticResolver{m: m}
}

type staticResolver struct{ m Model }

func (r staticResolver) ModelFor(context.Context, string) (Model, error) { return r.m, nil }

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
