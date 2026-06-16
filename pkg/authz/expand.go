package authz

import (
	"context"
	"fmt"
)

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

// Expand returns the userset tree for namespace:objectID#relation.
func (e *Engine) Expand(ctx context.Context, projectID, namespace, objectID, relation string) (Tree, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return Tree{}, err
	}
	return e.expand(ctx, m, projectID, namespace, objectID, relation, map[string]bool{}, 0)
}

func (e *Engine) expand(ctx context.Context, m Model, projectID, ns, obj, rel string, visited map[string]bool, depth int) (Tree, error) {
	self := SubjectSet{Namespace: ns, ObjectID: obj, Relation: rel}
	if depth > e.maxDepth {
		return Tree{Expanded: self}, fmt.Errorf("authz: max recursion depth exceeded at %s", visitKey(ns, obj, rel))
	}
	key := visitKey(ns, obj, rel)
	if visited[key] {
		return Tree{Expanded: self}, nil
	}
	visited[key] = true
	defer delete(visited, key)
	return e.expandRewrite(ctx, m, projectID, ns, obj, rel, self, m.rewrite(ns, rel), visited, depth)
}

func (e *Engine) expandRewrite(ctx context.Context, m Model, projectID, ns, obj, rel string, self SubjectSet, rw Rewrite, visited map[string]bool, depth int) (Tree, error) {
	switch {
	case rw.isThis():
		subjects, err := e.reader.ListSubjects(ctx, projectID, ns, obj, rel)
		if err != nil {
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
			sub, err := e.expandRewrite(ctx, m, projectID, ns, obj, rel, self, child, visited, depth)
			if err != nil {
				return Tree{}, err
			}
			node.Union = append(node.Union, sub)
		}
		return node, nil
	case len(rw.Intersection) > 0:
		node := Tree{Expanded: self}
		for _, child := range rw.Intersection {
			sub, err := e.expandRewrite(ctx, m, projectID, ns, obj, rel, self, child, visited, depth)
			if err != nil {
				return Tree{}, err
			}
			node.Intersection = append(node.Intersection, sub)
		}
		return node, nil
	case rw.Exclusion != nil:
		inc, err := e.expandRewrite(ctx, m, projectID, ns, obj, rel, self, rw.Exclusion.Include, visited, depth)
		if err != nil {
			return Tree{}, err
		}
		exc, err := e.expandRewrite(ctx, m, projectID, ns, obj, rel, self, rw.Exclusion.Exclude, visited, depth)
		if err != nil {
			return Tree{}, err
		}
		return Tree{Expanded: self, Exclude: &ExcludeTree{Include: inc, Exclude: exc}}, nil
	case rw.Computed != "":
		return e.expand(ctx, m, projectID, ns, obj, rw.Computed, visited, depth+1)
	case rw.TuplesetRelation != "":
		subjects, err := e.reader.ListSubjects(ctx, projectID, ns, obj, rw.TuplesetRelation)
		if err != nil {
			return Tree{}, err
		}
		node := Tree{Expanded: self}
		for _, s := range subjects {
			if s.Set == nil {
				continue
			}
			sub, err := e.expand(ctx, m, projectID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, visited, depth+1)
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
