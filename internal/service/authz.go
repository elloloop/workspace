package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// TupleOp is an insert or delete in a relation-tuple write.
type TupleOp struct {
	Delete bool
	Tuple  authz.Tuple
}

// WriteTuples applies raw relation-tuple writes for the caller's project and
// tenant. The caller is a trusted product backend holding a verified token;
// writes are scoped to its (project, tenant) shard and validated for shape.
func (s *Service) WriteTuples(ctx context.Context, p Principal, ops []TupleOp) error {
	var inserts, deletes []authz.Tuple
	for _, op := range ops {
		if err := validateTuple(op.Tuple); err != nil {
			return err
		}
		if op.Delete {
			deletes = append(deletes, op.Tuple)
		} else {
			inserts = append(inserts, op.Tuple)
		}
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return err
	}
	if err := s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, inserts, deletes); err != nil {
		return err
	}
	s.auditTupleChanges(ctx, p, inserts, deletes)
	return nil
}

// ensureProjectActive fails closed when the caller's project is suspended, so a
// suspended project's data plane stops authorizing and accepting writes.
func (s *Service) ensureProjectActive(ctx context.Context, p Principal) error {
	suspended, err := s.resolver.suspended(ctx, p.ProjectID)
	if err != nil {
		return err
	}
	if suspended {
		return fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	return nil
}

// ReadTuples returns stored tuples in the caller's project/tenant matching f.
func (s *Service) ReadTuples(ctx context.Context, p Principal, f TupleFilter) ([]authz.Tuple, error) {
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
	if res.suspended {
		return false, nil // a suspended project denies every check
	}
	allowed, err = s.engine.CheckWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, subjectUserID, reqContext)
	return allowed, err
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
	if res.suspended {
		return false, nil // a suspended project denies every check
	}
	allowed, err = s.engine.CheckSetWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, set, reqContext)
	return allowed, err
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
	if res.suspended {
		return authz.Tree{}, fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	tree, err := s.engine.ExpandWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, objectID, relation, s.maxExpandNodes)
	if errors.Is(err, authz.ErrExpandTooLarge) {
		return authz.Tree{}, fmt.Errorf("%w: expand result exceeds %d nodes; narrow the query", ErrResourceExhausted, s.maxExpandNodes)
	}
	return tree, err
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
	if res.suspended {
		return nil, fmt.Errorf("%w: project %q is suspended", ErrFailedPrecondition, p.ProjectID)
	}
	ids, err := s.engine.ListObjectsWithModel(ctx, res.modelOrDefault(), p.ProjectID, p.TenantID, namespace, relation, subjectUserID, s.maxListObjects)
	if errors.Is(err, authz.ErrTooManyObjects) {
		return nil, fmt.Errorf("%w: namespace has more than %d objects; narrow the query (pagination is a tracked follow-up)", ErrResourceExhausted, s.maxListObjects)
	}
	return ids, err
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
