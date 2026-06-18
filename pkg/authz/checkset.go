package authz

import "context"

// CheckSet answers whether the userset `set` has `relation` on
// namespace:objectID — "does the queried userset intersect the relation's
// effective userset". It is true when either:
//
//   - the queried set is structurally included in the target's userset (the
//     exact set is stored/derived under the relation, reachable through the
//     monotone union/computed/tuple-to-userset fragment), or the target grants
//     the public wildcard; OR
//   - any concrete member of the queried set has the relation.
//
// The member path OR's the existing concrete-user Check over EVERY member (not
// a single representative, which is wrong for nested groups). Structural
// matching deliberately does not pass through intersection/exclusion — those
// are answered soundly by member resolution. A query set whose own membership
// is the public wildcard ("everyone") intersects the target iff the target
// grants to at least one subject.
func (e *Engine) CheckSet(ctx context.Context, projectID, tenantID, namespace, objectID, relation string, set SubjectSet, cc map[string]any) (bool, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return false, err
	}
	return e.CheckSetWithModel(ctx, m, projectID, tenantID, namespace, objectID, relation, set, cc)
}

// CheckSetWithModel is CheckSet against an already-resolved model. cc is the
// request context conditional grants (caveats) are evaluated against, threaded
// to the target Check exactly as the concrete-user Check path does, so a
// conditional grant behaves identically whether queried by a user or a userset.
func (e *Engine) CheckSetWithModel(ctx context.Context, m Model, projectID, tenantID, namespace, objectID, relation string, set SubjectSet, cc map[string]any) (bool, error) {
	// ONE evalState — hence ONE read budget — is shared across the whole CheckSet
	// operation: the structural walk, member resolution (which expands usersets),
	// and the per-member Checks all charge the same budget, so a query set with
	// many members over a deep/cyclic graph cannot blow up unbounded. visited/memo
	// are reset between independent top-level Checks because the memo key omits the
	// query's object id (reusing it across different objects would be unsound).
	st := newEvalState(e.maxReads)

	// (1) structural inclusion through the monotone fragment, or target-public.
	ok, err := e.check(ctx, m, projectID, tenantID, namespace, objectID, relation, subjectQuery{set: &set}, cc, false, st, 0)
	if err != nil || ok {
		return ok, err
	}

	// (2) member intersection: any concrete member of the query set has access.
	// Membership resolution is condition-independent; the conditional grant on
	// the TARGET is evaluated by the per-member Check below (with cc).
	members, everyone, err := e.resolveMembers(ctx, m, projectID, tenantID, set, st, map[string]bool{}, 0)
	if err != nil {
		return false, err
	}
	for u := range members {
		st.visited = map[string]bool{}
		st.memo = map[string]bool{}
		ok, err := e.check(ctx, m, projectID, tenantID, namespace, objectID, relation, subjectQuery{user: u}, cc, false, st, 0)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	// (3) query set is unbounded ("everyone"): it intersects the target iff the
	// target grants to at least one subject. (A target wildcard was already
	// caught by the structural walk in step 1.)
	if everyone {
		tgt, tgtEveryone, err := e.resolveMembers(ctx, m, projectID, tenantID,
			SubjectSet{Namespace: namespace, ObjectID: objectID, Relation: relation}, st, map[string]bool{}, 0)
		if err != nil {
			return false, err
		}
		if tgtEveryone || len(tgt) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// resolveMembers resolves a userset to the set of concrete users that satisfy
// it, by expanding the userset tree and evaluating its set algebra. everyone is
// true when the membership includes the public wildcard (an unbounded set that
// cannot be enumerated). visited + maxDepth bound cycles and runaway recursion.
func (e *Engine) resolveMembers(ctx context.Context, m Model, projectID, tenantID string, set SubjectSet, st *evalState, visited map[string]bool, depth int) (map[string]struct{}, bool, error) {
	if depth > e.maxDepth {
		// Fail closed GRACEFULLY (consistent with Check/Expand): a too-deep or
		// cyclic userset resolves to no members rather than erroring, so a deep
		// chain can never turn CheckSet into a CodeInternal (500) / deep-nest DoS.
		recordBackstop(ctx, BackstopDepth)
		return map[string]struct{}{}, false, nil
	}
	key := visitKey(set.Namespace, set.ObjectID, set.Relation)
	if visited[key] {
		recordBackstop(ctx, BackstopCycle)
		return map[string]struct{}{}, false, nil // cycle: contributes no members
	}
	visited[key] = true
	defer delete(visited, key)

	count := 0
	tree, err := e.expand(ctx, m, projectID, tenantID, set.Namespace, set.ObjectID, set.Relation, &count, 0, st, map[string]bool{}, depth)
	if err != nil {
		return nil, false, err
	}
	return e.membersOfTree(ctx, m, projectID, tenantID, tree, st, visited, depth)
}

// membersOfTree evaluates an expanded userset tree to the concrete users it
// grants, applying the set algebra of union/intersection/exclusion. The bool is
// true when the result is the unbounded "everyone" set (a public wildcard).
func (e *Engine) membersOfTree(ctx context.Context, m Model, projectID, tenantID string, t Tree, st *evalState, visited map[string]bool, depth int) (map[string]struct{}, bool, error) {
	switch {
	case len(t.Union) > 0:
		out := map[string]struct{}{}
		everyone := false
		for _, c := range t.Union {
			cu, ce, err := e.membersOfTree(ctx, m, projectID, tenantID, c, st, visited, depth)
			if err != nil {
				return nil, false, err
			}
			for u := range cu {
				out[u] = struct{}{}
			}
			everyone = everyone || ce
		}
		return out, everyone, nil

	case len(t.Intersection) > 0:
		// members in EVERY child. An "everyone" child does not restrict the set.
		var acc map[string]struct{}
		bounded := false
		for _, c := range t.Intersection {
			cu, ce, err := e.membersOfTree(ctx, m, projectID, tenantID, c, st, visited, depth)
			if err != nil {
				return nil, false, err
			}
			if ce {
				continue // everyone ∩ X = X
			}
			if !bounded {
				acc, bounded = cu, true
			} else {
				acc = intersectUsers(acc, cu)
			}
		}
		if !bounded {
			return map[string]struct{}{}, true, nil // every child was everyone
		}
		return acc, false, nil

	case t.Exclude != nil:
		inc, incEveryone, err := e.membersOfTree(ctx, m, projectID, tenantID, t.Exclude.Include, st, visited, depth)
		if err != nil {
			return nil, false, err
		}
		exc, _, err := e.membersOfTree(ctx, m, projectID, tenantID, t.Exclude.Exclude, st, visited, depth)
		if err != nil {
			return nil, false, err
		}
		out := map[string]struct{}{}
		for u := range inc {
			if _, excluded := exc[u]; !excluded {
				out[u] = struct{}{}
			}
		}
		// If the include side is unbounded, the difference is unbounded too —
		// the concrete exclusions cannot be subtracted from an enumerable set.
		return out, incEveryone, nil

	default: // leaf
		out := map[string]struct{}{}
		for _, u := range t.Users {
			out[u] = struct{}{}
		}
		everyone := t.Wildcard
		for _, s := range t.Sets {
			su, se, err := e.resolveMembers(ctx, m, projectID, tenantID, s, st, visited, depth+1)
			if err != nil {
				return nil, false, err
			}
			for u := range su {
				out[u] = struct{}{}
			}
			everyone = everyone || se
		}
		return out, everyone, nil
	}
}

func intersectUsers(a, b map[string]struct{}) map[string]struct{} {
	if len(b) < len(a) {
		a, b = b, a
	}
	out := map[string]struct{}{}
	for u := range a {
		if _, ok := b[u]; ok {
			out[u] = struct{}{}
		}
	}
	return out
}
