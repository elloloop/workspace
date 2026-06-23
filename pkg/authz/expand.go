package authz

import (
	"context"
	"errors"
)

// ErrExpandTooLarge is returned by Expand when the expanded tree would exceed
// the caller-supplied node cap, so a single cheap request cannot amplify into an
// unbounded response. A non-positive cap disables the bound.
var ErrExpandTooLarge = errors.New("authz: expand result exceeds the node cap")

// bump charges n nodes against the budget, erroring once the running count
// exceeds max. A non-positive max means unbounded.
func bump(count *int, max, n int) error {
	*count += n
	if max > 0 && *count > max {
		return ErrExpandTooLarge
	}
	return nil
}

// Tree is the expanded userset for a relation. A node is one of: a leaf
// (concrete users, unexpanded usersets, and/or a public wildcard), a union,
// an intersection, or an exclusion of child trees.
type Tree struct {
	// Expanded is the userset this node corresponds to.
	Expanded SubjectSet
	// Union holds child subtrees; non-empty iff this is a union node.
	Union []Tree
	// Intersection holds child subtrees; non-empty iff this is an
	// intersection node (the subject must be in EVERY child).
	Intersection []Tree
	// Exclude, when non-nil, makes this an exclusion node: Include minus
	// Exclude.
	Exclude *ExcludeTree
	// Users and Sets are the leaf contents; set iff this is a leaf node.
	Users []string
	Sets  []SubjectSet
	// Wildcard is true on a leaf that includes the public "everyone" subject.
	Wildcard bool
}

// ExcludeTree is the expanded form of an exclusion rewrite.
type ExcludeTree struct {
	Include Tree
	Exclude Tree
}

// Expand returns the userset tree for namespace:objectID#relation. maxNodes
// caps the total number of tree nodes and leaf subjects (ErrExpandTooLarge past
// the cap); a non-positive maxNodes is unbounded.
func (e *Engine) Expand(ctx context.Context, projectID, tenantID, namespace, objectID, relation string, maxNodes int) (Tree, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return Tree{}, err
	}
	return e.ExpandWithModel(ctx, m, projectID, tenantID, namespace, objectID, relation, maxNodes, 0)
}

// ExpandWithModel is Expand against an already-resolved model. maxReads is a
// per-request read-budget override (> 0 wins, <= 0 falls back to the engine
// default) that bases the expand budget.
func (e *Engine) ExpandWithModel(ctx context.Context, m Model, projectID, tenantID, namespace, objectID, relation string, maxNodes, maxReads int) (Tree, error) {
	count := 0
	return e.expand(ctx, m, projectID, tenantID, namespace, objectID, relation, &count, maxNodes, newEvalState(e.expandBudget(e.effectiveMaxReads(maxReads), maxNodes)), map[string]bool{}, 0)
}

func (e *Engine) expand(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel string, count *int, max int, st *evalState, visited map[string]bool, depth int) (Tree, error) {
	self := SubjectSet{Namespace: ns, ObjectID: obj, Relation: rel}
	if depth > e.maxDepth {
		// Fail closed GRACEFULLY (consistent with Check/CheckSet): truncate the
		// tree at a bare leaf rather than erroring, so a deeply nested or cyclic
		// hierarchy can never turn Expand into a CodeInternal (500) / deep-nest DoS.
		recordBackstop(ctx, BackstopDepth)
		return Tree{Expanded: self}, nil
	}
	key := visitKey(ns, obj, rel)
	if visited[key] {
		recordBackstop(ctx, BackstopCycle)
		return Tree{Expanded: self}, nil
	}
	visited[key] = true
	defer delete(visited, key)
	return e.expandRewrite(ctx, m, projectID, tenantID, ns, obj, rel, self, m.rewrite(ns, rel), count, max, st, visited, depth)
}

func (e *Engine) expandRewrite(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel string, self SubjectSet, rw Rewrite, count *int, max int, st *evalState, visited map[string]bool, depth int) (Tree, error) {
	if err := bump(count, max, 1); err != nil { // one node per rewrite expansion
		return Tree{}, err
	}
	switch {
	case rw.isThis():
		if err := st.charge(); err != nil {
			recordBackstop(ctx, BackstopBudget)
			return Tree{}, err
		}
		subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rel)
		if err != nil {
			return Tree{}, err
		}
		if err := bump(count, max, len(subjects)); err != nil {
			return Tree{}, err
		}
		leaf := Tree{Expanded: self}
		for _, s := range subjects {
			switch {
			case s.Wildcard:
				leaf.Wildcard = true
			case s.Set == nil:
				leaf.Users = append(leaf.Users, s.UserID)
			default:
				leaf.Sets = append(leaf.Sets, *s.Set)
			}
		}
		return leaf, nil
	case len(rw.Union) > 0:
		node := Tree{Expanded: self}
		for _, child := range rw.Union {
			sub, err := e.expandRewrite(ctx, m, projectID, tenantID, ns, obj, rel, self, child, count, max, st, visited, depth)
			if err != nil {
				return Tree{}, err
			}
			node.Union = append(node.Union, sub)
		}
		return node, nil
	case len(rw.Intersection) > 0:
		node := Tree{Expanded: self}
		for _, child := range rw.Intersection {
			sub, err := e.expandRewrite(ctx, m, projectID, tenantID, ns, obj, rel, self, child, count, max, st, visited, depth)
			if err != nil {
				return Tree{}, err
			}
			node.Intersection = append(node.Intersection, sub)
		}
		return node, nil
	case rw.Exclusion != nil:
		inc, err := e.expandRewrite(ctx, m, projectID, tenantID, ns, obj, rel, self, rw.Exclusion.Include, count, max, st, visited, depth)
		if err != nil {
			return Tree{}, err
		}
		exc, err := e.expandRewrite(ctx, m, projectID, tenantID, ns, obj, rel, self, rw.Exclusion.Exclude, count, max, st, visited, depth)
		if err != nil {
			return Tree{}, err
		}
		return Tree{Expanded: self, Exclude: &ExcludeTree{Include: inc, Exclude: exc}}, nil
	case rw.Computed != "":
		return e.expand(ctx, m, projectID, tenantID, ns, obj, rw.Computed, count, max, st, visited, depth+1)
	case rw.TuplesetRelation != "":
		if err := st.charge(); err != nil {
			recordBackstop(ctx, BackstopBudget)
			return Tree{}, err
		}
		subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rw.TuplesetRelation)
		if err != nil {
			return Tree{}, err
		}
		node := Tree{Expanded: self}
		for _, s := range subjects {
			if s.Set == nil {
				continue
			}
			sub, err := e.expand(ctx, m, projectID, tenantID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, count, max, st, visited, depth+1)
			if err != nil {
				return Tree{}, err
			}
			node.Union = append(node.Union, sub)
		}
		return node, nil
	default:
		return Tree{Expanded: self}, nil
	}
}
