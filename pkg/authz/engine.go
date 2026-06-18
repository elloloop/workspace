package authz

import (
	"context"
	"errors"
	"strconv"
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

// maxRecursionDepth bounds rewrite recursion as a cycle/runaway backstop, and so
// bounds worst-case per-request cost (a poisoning cycle degrades the memo to
// O(depth^2)). Kept at the historical 32 — ample for nested folder/collection
// hierarchies in practice — rather than raised, so this feature adds no new
// cost ceiling for any recursive relation. Past it the engine fails closed
// gracefully on EVERY path (Check, Expand, CheckSet): a clean deny / truncated
// tree, never an error. Deeper nesting + a tighter per-request read budget are
// tracked as a follow-up.
const maxRecursionDepth = 32

// ErrEvalBudgetExceeded is returned by Check/CheckSet/Expand/ListObjects when a
// single operation's store-read budget is exhausted. Unlike the depth/cycle
// backstop (a graceful fail-closed deny), an exhausted budget is an ERROR: it
// means a pathological/abusive query (a planted cycle that poisons the memo, or
// a wide×deep branching graph), and a silent wrong-deny would both hide the
// abuse and under-grant. The service maps it to ErrResourceExhausted →
// connect.CodeResourceExhausted.
var ErrEvalBudgetExceeded = errors.New("authz: per-request read budget exceeded")

// evalState is the per-operation scratch state: the path-local cycle guard, a
// request-scoped result memo, a counter of cycle/depth hits used to decide which
// results are safe to memoize, and the store-read budget. q and cc are fixed for
// the lifetime of one evalState, so the memo key need not include them.
//
// The read budget is the unit of store WORK: every reader.ListSubjects call
// charges one read. maxReads caps the total across the whole operation; a
// non-positive maxReads is unbounded. ListObjects shares ONE evalState (hence
// one budget) across all its candidate Checks, so a wide namespace × deep graph
// cannot multiply into N×budget reads.
type evalState struct {
	visited    map[string]bool
	memo       map[string]bool
	cyclesSeen int
	reads      int
	maxReads   int
}

func newEvalState(maxReads int) *evalState {
	return &evalState{visited: map[string]bool{}, memo: map[string]bool{}, maxReads: maxReads}
}

// charge accounts one store read against the budget, returning
// ErrEvalBudgetExceeded once the count exceeds maxReads. A non-positive maxReads
// is unbounded. The fast path is a single increment + compare.
func (st *evalState) charge() error {
	st.reads++
	if st.maxReads > 0 && st.reads > st.maxReads {
		return ErrEvalBudgetExceeded
	}
	return nil
}

// Engine evaluates Check/Expand against a per-project model and a tuple store.
type Engine struct {
	resolver ModelResolver
	reader   TupleReader
	// maxDepth bounds rewrite recursion as a cycle/runaway backstop.
	maxDepth int
	// maxReads bounds the number of store reads (reader.ListSubjects calls) a
	// single Check/CheckSet/Expand/ListObjects operation may perform, so a
	// pathological cyclic/branching graph cannot make one request do unbounded
	// store work. Non-positive = unbounded.
	maxReads int
}

// NewEngine builds an engine. A nil resolver falls back to the built-in
// DefaultModel for every project. The read budget is unbounded until set with
// WithMaxReads.
func NewEngine(resolver ModelResolver, reader TupleReader) *Engine {
	if resolver == nil {
		resolver = StaticResolver(DefaultModel())
	}
	return &Engine{resolver: resolver, reader: reader, maxDepth: maxRecursionDepth}
}

// WithMaxReads sets the per-request store-read budget. A non-positive value
// leaves the budget unbounded.
func (e *Engine) WithMaxReads(n int) *Engine {
	if n > 0 {
		e.maxReads = n
	}
	return e
}

// subjectQuery is what a Check is testing for: exactly one of a concrete user
// or a userset (Set). The recursion threads it unchanged; only evalThis's
// terminal consults it, so the concrete-user path is identical to before.
type subjectQuery struct {
	user string
	set  *SubjectSet
}

// Check answers whether userID has relation on namespace:objectID, applying
// the project's namespace userset-rewrite rules transitively.
func (e *Engine) Check(ctx context.Context, projectID, tenantID, namespace, objectID, relation, userID string, cc map[string]any) (bool, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return false, err
	}
	return e.CheckWithModel(ctx, m, projectID, tenantID, namespace, objectID, relation, userID, cc)
}

// CheckWithModel is Check against an already-resolved model, so a caller that
// has resolved the project once (e.g. for a suspension check) does not trigger a
// second resolve.
func (e *Engine) CheckWithModel(ctx context.Context, m Model, projectID, tenantID, namespace, objectID, relation, userID string, cc map[string]any) (bool, error) {
	return e.check(ctx, m, projectID, tenantID, namespace, objectID, relation, subjectQuery{user: userID}, cc, false, newEvalState(e.maxReads), 0)
}

func visitKey(ns, obj, rel string) string { return ns + ":" + obj + "#" + rel }

// check evaluates a relation, carrying both the query subject and a negation
// polarity. negated is true under an odd number of exclusion-Exclude branches and
// only changes what a CYCLE defaults to: positive context a cycle contributes
// nothing (false); negated context a cycle fails CLOSED (true = "excluded"), so a
// self-referential block/suspend denies instead of fanning open.
func (e *Engine) check(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel string, q subjectQuery, cc map[string]any, negated bool, st *evalState, depth int) (bool, error) {
	key := visitKey(ns, obj, rel)
	if st.visited[key] {
		// Cycle back to an in-progress ancestor: positive context contributes
		// nothing (false); negated context fails CLOSED (true = "excluded"). Mark
		// the request as having touched a cycle so no ancestor caches a
		// path-dependent result below.
		st.cyclesSeen++
		recordBackstop(ctx, BackstopCycle)
		return negated, nil
	}
	if depth > e.maxDepth {
		// Runaway / over-deep chain: fail CLOSED gracefully (same polarity as a
		// cycle) rather than erroring — a deeply nested hierarchy yields a clean
		// deny, never a CodeInternal, and cannot be weaponized into 500s.
		st.cyclesSeen++
		recordBackstop(ctx, BackstopDepth)
		return negated, nil
	}
	mk := key + "\x1f" + strconv.FormatBool(negated)
	if r, ok := st.memo[mk]; ok {
		return r, nil
	}

	st.visited[key] = true
	before := st.cyclesSeen
	res, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, m.rewrite(ns, rel), negated, st, depth)
	delete(st.visited, key)
	// A node's result for the request's fixed (q, cc, negated) is path-independent
	// UNLESS its subtree touched a cycle/depth-limit (returns the polarity default
	// of the in-progress ancestor). Cache only when the subtree was clean — so an
	// acyclic folder DAG collapses to one evaluation per node, while cyclic models
	// recompute and stay fail-closed exactly as before.
	if err == nil && st.cyclesSeen == before {
		st.memo[mk] = res
	}
	return res, err
}

func (e *Engine) evalRewrite(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel string, q subjectQuery, cc map[string]any, rw Rewrite, negated bool, st *evalState, depth int) (bool, error) {
	switch {
	case rw.isThis():
		return e.evalThis(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, negated, st, depth)
	case len(rw.Union) > 0:
		for _, child := range rw.Union {
			ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, child, negated, st, depth)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case len(rw.Intersection) > 0:
		// A userset query is answered structurally only through the monotone
		// fragment; intersection (and exclusion below) can make a structural
		// set-match unsound (the set looks included while every member is
		// filtered out), so defer to CheckSet's per-member resolution.
		if q.set != nil {
			return false, nil
		}
		for _, child := range rw.Intersection {
			ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, child, negated, st, depth)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case rw.Exclusion != nil:
		if q.set != nil {
			return false, nil // a set query cannot be matched structurally through exclusion
		}
		ok, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, rw.Exclusion.Include, negated, st, depth)
		if err != nil || !ok {
			return false, err
		}
		// The Exclude branch flips polarity: a cycle here must fail closed.
		excluded, err := e.evalRewrite(ctx, m, projectID, tenantID, ns, obj, rel, q, cc, rw.Exclusion.Exclude, !negated, st, depth)
		if err != nil {
			return false, err
		}
		return !excluded, nil
	case rw.Computed != "":
		return e.check(ctx, m, projectID, tenantID, ns, obj, rw.Computed, q, cc, negated, st, depth+1)
	case rw.TuplesetRelation != "":
		return e.evalTupleToUserset(ctx, m, projectID, tenantID, ns, obj, rw, q, cc, negated, st, depth)
	default:
		return false, nil
	}
}

// evalThis evaluates the directly stored tuples for a relation. A public wildcard
// matches any query. For a concrete-user query, a matching stored user matches and
// a stored userset is followed recursively. For a userset query, a stored set EQUAL
// to the query matches structurally (other stored sets are followed, so the query
// can be matched transitively/nested); concrete members of the query are handled by
// CheckSet's member resolution.
func (e *Engine) evalThis(ctx context.Context, m Model, projectID, tenantID, ns, obj, rel string, q subjectQuery, cc map[string]any, negated bool, st *evalState, depth int) (bool, error) {
	if err := st.charge(); err != nil {
		recordBackstop(ctx, BackstopBudget)
		return false, err
	}
	subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rel)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		// A conditional grant applies only when its condition holds against the
		// request context; a nil condition always holds. Fails closed (unknown
		// condition / missing input / ill-typed value => the grant is skipped).
		if !EvalCondition(s.Condition, cc) {
			continue
		}
		if s.Wildcard {
			return true, nil // public grant: matches any user or set query
		}
		if s.Set == nil {
			if q.user != "" && s.UserID == q.user {
				return true, nil
			}
			continue
		}
		if q.set != nil && *s.Set == *q.set {
			return true, nil // structural match: the queried userset is stored here
		}
		ok, err := e.check(ctx, m, projectID, tenantID, s.Set.Namespace, s.Set.ObjectID, s.Set.Relation, q, cc, negated, st, depth+1)
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
func (e *Engine) evalTupleToUserset(ctx context.Context, m Model, projectID, tenantID, ns, obj string, rw Rewrite, q subjectQuery, cc map[string]any, negated bool, st *evalState, depth int) (bool, error) {
	if err := st.charge(); err != nil {
		recordBackstop(ctx, BackstopBudget)
		return false, err
	}
	subjects, err := e.reader.ListSubjects(ctx, projectID, tenantID, ns, obj, rw.TuplesetRelation)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if !EvalCondition(s.Condition, cc) {
			continue // a conditional tupleset pointer applies only when its condition holds
		}
		if s.Set == nil {
			continue // tupleset entries must be usersets to walk
		}
		ok, err := e.check(ctx, m, projectID, tenantID, s.Set.Namespace, s.Set.ObjectID, rw.ComputedRelation, q, cc, negated, st, depth+1)
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
// ErrTooManyObjects is returned by ListObjects when the candidate set exceeds
// the caller-supplied cap. ListObjects is a full scan + per-object Check, so an
// unbounded namespace would otherwise run for minutes and exhaust the pool; the
// cap bounds the work. (A reverse index / pagination is the tracked follow-up.)
var ErrTooManyObjects = errors.New("authz: too many candidate objects for ListObjects")

func (e *Engine) ListObjects(ctx context.Context, projectID, tenantID, namespace, relation, userID string, maxObjects int) ([]string, error) {
	m, err := e.resolver.ModelFor(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return e.ListObjectsWithModel(ctx, m, projectID, tenantID, namespace, relation, userID, maxObjects)
}

// ListObjectsWithModel is ListObjects against an already-resolved model; the
// per-object Check reuses that model rather than re-resolving the project for
// every candidate.
func (e *Engine) ListObjectsWithModel(ctx context.Context, m Model, projectID, tenantID, namespace, relation, userID string, maxObjects int) ([]string, error) {
	lister, ok := e.reader.(ObjectLister)
	if !ok {
		return nil, errors.New("authz: tuple store does not support ListObjects")
	}
	ids, err := lister.ListObjectIDs(ctx, projectID, tenantID, namespace)
	if err != nil {
		return nil, err
	}
	if maxObjects > 0 && len(ids) > maxObjects {
		return nil, ErrTooManyObjects
	}
	// ONE evalState — hence ONE read budget — is shared across every candidate
	// Check. A fresh evalState per candidate would give the budget no teeth: a
	// wide namespace × deep/cyclic graph could each stay just under the per-Check
	// budget yet do N×budget total store work. The memo is intentionally NOT
	// shared, because it is keyed on (object,relation,negated) without the object
	// id of the top-level query; reusing it across candidates would be unsound.
	st := newEvalState(e.maxReads)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		st.visited = map[string]bool{}
		st.memo = map[string]bool{}
		ok, err := e.check(ctx, m, projectID, tenantID, namespace, id, relation, subjectQuery{user: userID}, nil, false, st, 0)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, id)
		}
	}
	return out, nil
}
