package authz

import (
	"context"
	"fmt"
)

// TupleReader is the store boundary the engine reads through. It returns the
// subjects directly stored for a (project, tenant, namespace, object,
// relation) — no rewrite evaluation. Implemented by the repo drivers.
//
// project_id and tenant_id are the isolation shard pair (identity ADR-0002):
// project_id is the configuration/model boundary, tenant_id the data-isolation
// boundary within a project. An empty tenant_id is the project's default
// tenant.
type TupleReader interface {
	ListSubjects(ctx context.Context, projectID, tenantID, namespace, objectID, relation string) ([]Subject, error)
}

// ObjectLister is an optional store capability: list the distinct object_ids
// that have any stored tuple for (project, tenant, namespace). It bounds the
// candidate set ListObjects evaluates.
type ObjectLister interface {
	ListObjectIDs(ctx context.Context, projectID, tenantID, namespace string) ([]string, error)
}

// Engine evaluates Check/Expand against a per-project model and a tuple store.
type Engine struct {
	resolver ModelResolver
	reader   TupleReader
	// maxDepth bounds rewrite recursion as a cycle/runaway backstop.
	maxDepth int
}

// NewEngine builds an engine. A nil resolver falls back to the built-in
// DefaultModel for every project.
func NewEngine(resolver ModelResolver, reader TupleReader) *Engine {
	if resolver == nil {
		resolver = StaticResolver(DefaultModel())
	}
	return &Engine{resolver: resolver, reader: reader, maxDepth: 32}
}

// Check answers whether userID has relation on namespace:objectID, applying
// the project's namespace userset-rewrite rules transitively.
func (e *Engine) Check(ctx context.Context, projectID, tenantID, namespace, objectID, relation, userID string) (bool, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return false, err
	}
	return e.check(ctx, m, projectID, tenantID, namespace, objectID, relation, userID, map[string]bool{}, 0)
}

func visitKey(ns, obj, rel string) string { return ns + ":" + obj + "#" + rel }

func (e *Engine) check(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel, userID string, visited map[string]bool, depth int) (bool, error) {
	if depth > e.maxDepth {
		return false, fmt.Errorf("authz: max recursion depth exceeded at %s", visitKey(ns, obj, rel))
	}
	key := visitKey(ns, obj, rel)
	if visited[key] {
		return false, nil // cycle: this branch contributes nothing
	}
	visited[key] = true
	defer delete(visited, key)

	return e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, userID, m.rewrite(ns, rel), visited, depth)
}

func (e *Engine) evalRewrite(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel, userID string, rw Rewrite, visited map[string]bool, depth int) (bool, error) {
	switch {
	case rw.isThis():
		return e.evalThis(ctx, m, projectID, tenantID, ns, obj, rel, userID, visited, depth)
	case len(rw.Union) > 0:
		for _, child := range rw.Union {
			ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, userID, child, visited, depth)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case len(rw.Intersection) > 0:
		for _, child := range rw.Intersection {
			ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, userID, child, visited, depth)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case rw.Exclusion != nil:
		ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, userID, rw.Exclusion.Include, visited, depth)
		if err != nil || !ok {
			return false, err
		}
		excluded, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, userID, rw.Exclusion.Exclude, visited, depth)
		if err != nil {
			return false, err
		}
		return !excluded, nil
	case rw.Computed != "":
		return e.check(ctx, m, projectID, tenantID, ns, obj, rw.Computed, userID, visited, depth+1)
	case rw.TuplesetRelation != "":
		return e.evalTupleToUserset(ctx, m, projectID, tenantID, ns, obj, rw, userID, visited, depth)
	default:
		return false, nil
	}
}

// evalThis evaluates the directly stored tuples for a relation: a wildcard
// matches any user; a concrete user matches outright; a userset subject is
// followed recursively.
func (e *Engine) evalThis(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel, userID string, visited map[string]bool, depth int) (bool, error) {
	subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rel)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if s.Wildcard {
			return true, nil // public grant: matches any user
		}
		if s.Set == nil {
			if s.UserID == userID {
				return true, nil
			}
			continue
		}
		ok, err := e.check(ctx, m, projectID, tenantID, s.Set.Namespace, s.Set.ObjectID, s.Set.Relation, userID, visited, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// evalTupleToUserset walks every userset stored under the tupleset relation
// and checks the computed relation on each referenced object.
func (e *Engine) evalTupleToUserset(ctx context.Context, m Model, projectID, tenantID, ns, obj string, rw Rewrite, userID string, visited map[string]bool, depth int) (bool, error) {
	subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rw.TuplesetRelation)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if s.Set == nil {
			continue // tupleset entries must be usersets to walk
		}
		ok, err := e.check(ctx, m, projectID, tenantID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, userID, visited, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ListObjects returns the object_ids in a namespace where userID has the
// relation, for the given project/tenant. It is correctness-first: it bounds
// the candidate set to objects that have any stored tuple in the namespace
// (via an ObjectLister reader) and evaluates Check on each. A reverse-index
// optimization for large namespaces is a tracked follow-up.
func (e *Engine) ListObjects(ctx context.Context, projectID, tenantID, namespace, relation, userID string) ([]string, error) {
	lister, ok := e.reader.(ObjectLister)
	if !ok {
		return nil, fmt.Errorf("authz: tuple store does not support ListObjects")
	}
	ids, err := lister.ListObjectIDs(ctx, projectID, tenantID, namespace)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		ok, err := e.Check(ctx, projectID, tenantID, namespace, id, relation, userID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	return out, nil
}
