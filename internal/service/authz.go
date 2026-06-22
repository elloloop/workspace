package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/workspace/internal/consistencytoken"
	"github.com/elloloop/workspace/pkg/authz"
)

// TupleOp is an insert or delete in a relation-tuple write.
type TupleOp struct {
	Delete bool
	Tuple  authz.Tuple
}

// WriteTuples applies raw relation-tuple writes for the caller's project and
// tenant. The caller is a trusted product backend holding a verified token;
// writes are scoped to its (project, tenant) shard and validated for shape. It
// returns an opaque consistency token naming the shard's write sequence reached
// by this batch; a caller may pass it to a later read (EnsureConsistency) to
// demand read-after-write — observing at least this write.
func (s *Service) WriteTuples(ctx context.Context, p Principal, ops []TupleOp) (string, error) {
	var inserts, deletes []authz.Tuple
	for _, op := range ops {
		if err := validateTuple(op.Tuple); err != nil {
			return "", err
		}
		if op.Delete {
			deletes = append(deletes, op.Tuple)
		} else {
			inserts = append(inserts, op.Tuple)
		}
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return "", err
	}
	// Reject INSERTs on relations the project's model defines as computed-only
	// (no reachable `this` leg): the engine would never read such a tuple, so
	// storing it is an inert grant that ReadTuples would surface but Check would
	// ignore. DELETEs stay lenient, so a tuple minted before a model change can
	// still be cleaned up. Unknown relations default to `this` and remain writable.
	if len(inserts) > 0 {
		res, rerr := s.resolver.resolve(ctx, p.ProjectID)
		if rerr != nil {
			return "", rerr
		}
		m := res.modelOrDefault()
		for _, t := range inserts {
			if !m.WritableRelation(t.Namespace, t.Relation) {
				return "", fmt.Errorf("%w: relation %s#%s is computed-only and cannot be written directly",
					ErrInvalidArgument, t.Namespace, t.Relation)
			}
		}
	}
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, inserts, deletes); err != nil {
		return "", err
	}
	s.auditTupleChanges(ctx, p, inserts, deletes)
	seq, err := s.repo.ConsistencyToken(ctx, p.ProjectID, p.TenantID)
	if err != nil {
		return "", err
	}
	return consistencytoken.Encode(p.ProjectID, p.TenantID, seq), nil
}

// EnsureConsistency enforces a caller-supplied read-after-write token before a
// read. An empty token is a no-op (read latest — today's behavior). A malformed
// token, or one issued for a different (project, tenant) shard, is rejected
// (ErrInvalidArgument) rather than silently ignored. Otherwise the read must
// reflect state at least as fresh as the token: on this single primary store a
// read always sees every committed write, so any token the store could have
// issued (seq <= the shard's current sequence) is satisfied immediately; a token
// demanding state the store has not reached (a forged/foreign seq — or, once read
// replicas exist, a lagging replica) fails closed with ErrFailedPrecondition.
func (s *Service) EnsureConsistency(ctx context.Context, p Principal, token string) error {
	if token == "" {
		return nil
	}
	tok, err := consistencytoken.Decode(token)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	if tok.Project != p.ProjectID || tok.Tenant != p.TenantID {
		return fmt.Errorf("%w: consistency token is for a different project/tenant", ErrInvalidArgument)
	}
	current, err := s.repo.ConsistencyToken(ctx, p.ProjectID, p.TenantID)
	if err != nil {
		return err
	}
	if current < tok.Seq {
		return fmt.Errorf("%w: store has not reached the requested consistency sequence", ErrFailedPrecondition)
	}
	return nil
}

// ensureProjectActive fails closed when the caller's project is suspended or is
// pinned to a data region this instance does not serve, so a suspended or
// mis-routed project's data plane stops authorizing and accepting writes.
func (s *Service) ensureProjectActive(ctx context.Context, p Principal) error {
	res, err := s.resolver.resolve(ctx, p.ProjectID)
	if err != nil {
		return err
	}
	if err := s.regionServable(p, res); err != nil {
		return err
	}
	if res.suspended {
		return fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	return nil
}

// ReadTuples returns stored tuples in the caller's project/tenant matching f.
func (s *Service) ReadTuples(ctx context.Context, p Principal, f TupleFilter) ([]authz.Tuple, error) {
	if err := s.ensureRegion(ctx, p); err != nil {
		return nil, err
	}
	return s.repo.ReadTuples(ctx, p.ProjectID, p.TenantID, f)
}

// Check evaluates a permission for the caller's project and tenant. reqContext
// carries request-time attributes (e.g. age, consent, ip) that conditional
// grants (caveats) are evaluated against; pass nil when there is no context.
func (s *Service) Check(ctx context.Context, p Principal, namespace, objectID, relation, subjectUserID string, reqContext map[string]any) (allowed bool, err error) {
	if namespace == "" || objectID == "" || relation == "" || subjectUserID == "" {
		return false, fmt.Errorf("%w: namespace, object_id, relation, subject_user_id are required", ErrInvalidArgument)
	}
	// Emit an audit record for the final decision (after validation), never
	// affecting the result. The nil guard keeps this free when disabled.
	if s.decisionLog != nil {
		defer func() {
			s.decisionLog.Log(ctx, DecisionRecord{
				ProjectID: p.ProjectID, TenantID: p.TenantID,
				Namespace: namespace, ObjectID: objectID, Relation: relation,
				SubjectUserID: subjectUserID, Allowed: allowed, Err: errString(err),
				Caller: p.Caller, DecidedAt: s.now(),
			})
		}()
	}
	res, rerr := s.resolver.resolve(ctx, p.ProjectID)
	if rerr != nil {
		return false, rerr
	}
	if rerr := s.regionServable(p, res); rerr != nil {
		return false, rerr
	}
	if res.suspended {
		return false, nil // a suspended project denies every check
	}
	allowed, err = s.engine.CheckWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, subjectUserID, reqContext, res.maxCheckReads)
	return allowed, mapBudgetErr(err)
}

// mapBudgetErr translates the engine's per-request read-budget error into the
// service's ErrResourceExhausted sentinel (→ connect.CodeResourceExhausted). An
// exhausted budget means a pathological/abusive query; surfacing it as an error
// (not a silent deny) keeps it visible and avoids under-granting. Other errors
// and nil pass through unchanged.
func mapBudgetErr(err error) error {
	if errors.Is(err, authz.ErrEvalBudgetExceeded) {
		return fmt.Errorf("%w: evaluation exceeded the per-request read budget; the model graph for this query is too deep/branching/cyclic", ErrResourceExhausted)
	}
	return err
}

// CheckSet evaluates whether a USERSET (e.g. group:cohort-7#member) has the
// relation — "does the queried userset intersect the relation's effective
// userset". It mirrors Check (same suspension fail-closed AND the same
// reqContext for conditional grants) but for a set-valued query subject rather
// than a concrete user.
func (s *Service) CheckSet(ctx context.Context, p Principal, namespace, objectID, relation string, set authz.SubjectSet, reqContext map[string]any) (allowed bool, err error) {
	if namespace == "" || objectID == "" || relation == "" {
		return false, fmt.Errorf("%w: namespace, object_id, relation are required", ErrInvalidArgument)
	}
	if set.Namespace == "" || set.ObjectID == "" || set.Relation == "" {
		return false, fmt.Errorf("%w: subject_set requires namespace, object_id, and relation", ErrInvalidArgument)
	}
	if s.decisionLog != nil {
		ss := set
		defer func() {
			s.decisionLog.Log(ctx, DecisionRecord{
				ProjectID: p.ProjectID, TenantID: p.TenantID,
				Namespace: namespace, ObjectID: objectID, Relation: relation,
				SubjectSet: &ss, Allowed: allowed, Err: errString(err),
				Caller: p.Caller, DecidedAt: s.now(),
			})
		}()
	}
	res, rerr := s.resolver.resolve(ctx, p.ProjectID)
	if rerr != nil {
		return false, rerr
	}
	if rerr := s.regionServable(p, res); rerr != nil {
		return false, rerr
	}
	if res.suspended {
		return false, nil // a suspended project denies every check
	}
	allowed, err = s.engine.CheckSetWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, set, reqContext, res.maxCheckReads)
	return allowed, mapBudgetErr(err)
}

// Expand returns the userset tree for the caller's project and tenant.
func (s *Service) Expand(ctx context.Context, p Principal, namespace, objectID, relation string) (authz.Tree, error) {
	if namespace == "" || objectID == "" || relation == "" {
		return authz.Tree{}, fmt.Errorf("%w: namespace, object_id, relation are required", ErrInvalidArgument)
	}
	res, err := s.resolver.resolve(ctx, p.ProjectID)
	if err != nil {
		return authz.Tree{}, err
	}
	if err := s.regionServable(p, res); err != nil {
		return authz.Tree{}, err
	}
	if res.suspended {
		return authz.Tree{}, fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	tree, err := s.engine.ExpandWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, s.maxExpandNodes, res.maxCheckReads)
	if errors.Is(err, authz.ErrExpandTooLarge) {
		return authz.Tree{}, fmt.Errorf("%w: expand result exceeds %d nodes; narrow the query", ErrResourceExhausted, s.maxExpandNodes)
	}
	return tree, mapBudgetErr(err)
}

// ListObjects returns the object_ids in a namespace where subjectUserID has
// the relation, for the caller's project and tenant.
func (s *Service) ListObjects(ctx context.Context, p Principal, namespace, relation, subjectUserID string) ([]string, error) {
	if namespace == "" || relation == "" || subjectUserID == "" {
		return nil, fmt.Errorf("%w: namespace, relation, subject_user_id are required", ErrInvalidArgument)
	}
	res, err := s.resolver.resolve(ctx, p.ProjectID)
	if err != nil {
		return nil, err
	}
	if err := s.regionServable(p, res); err != nil {
		return nil, err
	}
	if res.suspended {
		return nil, fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	ids, err := s.engine.ListObjectsWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, relation, subjectUserID, s.maxListObjects, res.maxCheckReads)
	if errors.Is(err, authz.ErrTooManyObjects) {
		return nil, fmt.Errorf("%w: namespace has more than %d objects; narrow the query (pagination is a tracked follow-up)", ErrResourceExhausted, s.maxListObjects)
	}
	return ids, mapBudgetErr(err)
}

// DeprovisionUser revokes ALL of a subject's ACCESS GRANTS: it deletes every
// relation tuple whose concrete subject is userID across all namespaces AND ALL
// TENANTS of the caller's project, returning the count removed. It is
// intentionally project-wide (tenant_id on the request is ignored) so
// offboarding cannot leave the user with live grants in a sibling tenant, and it
// reaches grants held via group usersets that a per-subject sweep would miss.
//
// It does NOT delete the user's PII — membership/invitation/workspace rows are
// left intact. Full subject erasure (deleting those rows) and grant export for a
// data-subject request are a separate concern, tracked in issue #14; do not rely
// on this RPC alone for GDPR/COPPA "right to erasure".
func (s *Service) DeprovisionUser(ctx context.Context, p Principal, userID string) (int, error) {
	if userID == "" {
		return 0, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	if err := s.ensureRegion(ctx, p); err != nil {
		return 0, err
	}
	return s.repo.DeleteAllSubjectTuplesInProject(ctx, p.ProjectID, userID)
}

// SubjectGrant is one authorization grant a subject holds (for export). ViaGroup
// is empty for a DIRECT grant; otherwise it is the group id whose membership
// confers the grant.
type SubjectGrant struct {
	TenantID  string
	Namespace string
	ObjectID  string
	Relation  string
	ViaGroup  string
}

// ExportSubjectGrants returns every grant userID holds in the caller's project,
// across ALL tenants — direct tuples (which include the user's group
// memberships) plus one level of group-mediated grants — for a GDPR/COPPA
// data-subject access request. Read-only; it is an admin/export path and is not
// gated on project suspension (a suspended project's subjects must still be able
// to exercise access requests).
func (s *Service) ExportSubjectGrants(ctx context.Context, p Principal, userID string) ([]SubjectGrant, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	if err := s.ensureRegion(ctx, p); err != nil {
		return nil, err
	}
	direct, err := s.repo.ListSubjectTuplesInProject(ctx, p.ProjectID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]SubjectGrant, 0, len(direct))
	var groupSets []authz.SubjectSet
	for _, ta := range direct {
		out = append(out, SubjectGrant{
			TenantID:  ta.TenantID,
			Namespace: ta.Tuple.Namespace,
			ObjectID:  ta.Tuple.ObjectID,
			Relation:  ta.Tuple.Relation,
		})
		if ta.Tuple.Namespace == "group" && ta.Tuple.Relation == "member" {
			groupSets = append(groupSets, authz.SubjectSet{Namespace: "group", ObjectID: ta.Tuple.ObjectID, Relation: "member"})
		}
	}
	if len(groupSets) > 0 {
		viaGroup, err := s.repo.ListTuplesForSubjectSetsInProject(ctx, p.ProjectID, groupSets)
		if err != nil {
			return nil, err
		}
		for _, ta := range viaGroup {
			out = append(out, SubjectGrant{
				TenantID:  ta.TenantID,
				Namespace: ta.Tuple.Namespace,
				ObjectID:  ta.Tuple.ObjectID,
				Relation:  ta.Tuple.Relation,
				ViaGroup:  ta.Tuple.Subject.Set.ObjectID,
			})
		}
	}
	return out, nil
}

func validateTuple(t authz.Tuple) error {
	if t.Namespace == "" || t.ObjectID == "" || t.Relation == "" {
		return fmt.Errorf("%w: tuple namespace, object_id, relation are required", ErrInvalidArgument)
	}
	// The `seat` namespace is RESERVED: seat-holder tuples may only be minted or
	// removed through the cap-enforced AssignSeat/RevokeSeat (which write to the
	// store directly), never the generic tuple-write path — otherwise a paid
	// entitlement could be granted outside the counted/capped flow.
	if t.Namespace == seatNamespace {
		return fmt.Errorf("%w: the %q namespace is reserved; use AssignSeat/RevokeSeat", ErrInvalidArgument, seatNamespace)
	}
	// Reject control characters in every tuple string field. The memory driver's
	// keys length-prefix each component (collision-free regardless of contents),
	// but a control char in an id is never legitimate, so we fail closed here at
	// the durable seam — uniformly across all drivers — using the shared rule.
	for _, f := range []string{t.Namespace, t.ObjectID, t.Relation, t.Subject.UserID} {
		if HasControlChar(f) {
			return fmt.Errorf("%w: tuple fields must not contain control characters", ErrInvalidArgument)
		}
	}
	if st := t.Subject.Set; st != nil && (HasControlChar(st.Namespace) || HasControlChar(st.ObjectID) || HasControlChar(st.Relation)) {
		return fmt.Errorf("%w: tuple subject-set fields must not contain control characters", ErrInvalidArgument)
	}
	var set int
	if t.Subject.UserID != "" {
		set++
	}
	if t.Subject.Set != nil {
		set++
	}
	if t.Subject.Wildcard {
		set++
	}
	if set != 1 {
		return fmt.Errorf("%w: tuple subject must be exactly one of user_id, subject set, or wildcard", ErrInvalidArgument)
	}
	if t.Subject.Set != nil && (t.Subject.Set.Namespace == "" || t.Subject.Set.ObjectID == "") {
		return fmt.Errorf("%w: subject set requires namespace and object_id", ErrInvalidArgument)
	}
	if c := t.Subject.Condition; c != nil && c.Name != "" && !authz.KnownCondition(c.Name) {
		return fmt.Errorf("%w: unknown condition %q", ErrInvalidArgument, c.Name)
	}
	return nil
}
