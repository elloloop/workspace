package authz

import (
	"context"
	"fmt"
)

// TupleReader is the store boundary the engine reads through. It returns
// the subjects directly stored for a (project, namespace, object, relation)
// — no rewrite evaluation. Implemented by the repo drivers.
type TupleReader interface {
	ListSubjects(ctx context.Context, projectID, namespace, objectID, relation string) ([]Subject, error)
}

// Engine evaluates Check/Expand against a model and a tuple store.
type Engine struct {
	model  Model
	reader TupleReader
	// maxDepth bounds rewrite recursion as a cycle/runaway backstop.
	maxDepth int
}

// NewEngine builds an engine. A zero model falls back to DefaultModel.
func NewEngine(model Model, reader TupleReader) *Engine {
	if model == nil {
		model = DefaultModel()
	}
	return &Engine{model: model, reader: reader, maxDepth: 32}
}

// Check answers whether userID has relation on namespace:objectID, applying
// the namespace's userset-rewrite rules transitively.
func (e *Engine) Check(ctx context.Context, projectID, namespace, objectID, relation, userID string) (bool, error) {
	return e.check(ctx, projectID, namespace, objectID, relation, userID, map[string]bool{}, 0)
}

func visitKey(ns, obj, rel string) string { return ns + ":" + obj + "#" + rel }

func (e *Engine) check(ctx context.Context, projectID, ns, obj, rel, userID string, visited map[string]bool, depth int) (bool, error) {
	if depth > e.maxDepth {
		return false, fmt.Errorf("authz: max recursion depth exceeded at %s", visitKey(ns, obj, rel))
	}
	key := visitKey(ns, obj, rel)
	if visited[key] {
		return false, nil // cycle: this branch contributes nothing
	}
	visited[key] = true
	defer delete(visited, key)

	return e.evalRewrite(ctx, projectID, ns, obj, rel, userID, e.model.rewrite(ns, rel), visited, depth)
}

func (e *Engine) evalRewrite(ctx context.Context, projectID, ns, obj, rel, userID string, rw Rewrite, visited map[string]bool, depth int) (bool, error) {
	switch {
	case rw.isThis():
		return e.evalThis(ctx, projectID, ns, obj, rel, userID, visited, depth)
	case len(rw.Union) > 0:
		for _, child := range rw.Union {
			ok, err := e.evalRewrite(ctx, projectID, ns, obj, rel, userID, child, visited, depth)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case rw.Computed != "":
		return e.check(ctx, projectID, ns, obj, rw.Computed, userID, visited, depth+1)
	case rw.TuplesetRelation != "":
		return e.evalTupleToUserset(ctx, projectID, ns, obj, rw, userID, visited, depth)
	default:
		return false, nil
	}
}

// evalThis evaluates the directly stored tuples for a relation: a concrete
// user matches outright; a userset subject is followed recursively.
func (e *Engine) evalThis(ctx context.Context, projectID, ns, obj, rel, userID string, visited map[string]bool, depth int) (bool, error) {
	subjects, err := e.reader.ListSubjects(ctx, projectID, ns, obj, rel)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if s.Set == nil {
			if s.UserID == userID {
				return true, nil
			}
			continue
		}
		ok, err := e.check(ctx, projectID, s.Set.Namespace, s.Set.ObjectID, s.Set.Relation, userID, visited, depth+1)
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
func (e *Engine) evalTupleToUserset(ctx context.Context, projectID, ns, obj string, rw Rewrite, userID string, visited map[string]bool, depth int) (bool, error) {
	subjects, err := e.reader.ListSubjects(ctx, projectID, ns, obj, rw.TuplesetRelation)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if s.Set == nil {
			continue // tupleset entries must be usersets to walk
		}
		ok, err := e.check(ctx, projectID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, userID, visited, depth+1)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
