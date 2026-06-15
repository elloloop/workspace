package authz

import (
	"context"
	"fmt"
)

// Tree is the expanded userset for a relation. A node is either a leaf
// (concrete users plus unexpanded usersets) or a union of child trees.
type Tree struct {
	// Expanded is the userset this node corresponds to.
	Expanded SubjectSet
	// Union holds child subtrees; non-empty iff this is a union node.
	Union []Tree
	// Users and Sets are the leaf contents; set iff Union is empty.
	Users []string
	Sets  []SubjectSet
}

// Expand returns the userset tree for namespace:objectID#relation.
func (e *Engine) Expand(ctx context.Context, projectID, namespace, objectID, relation string) (Tree, error) {
	return e.expand(ctx, projectID, namespace, objectID, relation, map[string]bool{}, 0)
}

func (e *Engine) expand(ctx context.Context, projectID, ns, obj, rel string, visited map[string]bool, depth int) (Tree, error) {
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
	return e.expandRewrite(ctx, projectID, ns, obj, rel, self, e.model.rewrite(ns, rel), visited, depth)
}

func (e *Engine) expandRewrite(ctx context.Context, projectID, ns, obj, rel string, self SubjectSet, rw Rewrite, visited map[string]bool, depth int) (Tree, error) {
	switch {
	case rw.isThis():
		subjects, err := e.reader.ListSubjects(ctx, projectID, ns, obj, rel)
		if err != nil {
			return Tree{}, err
		}
		leaf := Tree{Expanded: self}
		for _, s := range subjects {
			if s.Set == nil {
				leaf.Users = append(leaf.Users, s.UserID)
			} else {
				leaf.Sets = append(leaf.Sets, *s.Set)
			}
		}
		return leaf, nil
	case len(rw.Union) > 0:
		node := Tree{Expanded: self}
		for _, child := range rw.Union {
			sub, err := e.expandRewrite(ctx, projectID, ns, obj, rel, self, child, visited, depth)
			if err != nil {
				return Tree{}, err
			}
			node.Union = append(node.Union, sub)
		}
		return node, nil
	case rw.Computed != "":
		return e.expand(ctx, projectID, ns, obj, rw.Computed, visited, depth+1)
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
			sub, err := e.expand(ctx, projectID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, visited, depth+1)
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
