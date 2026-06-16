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
	return s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, inserts, deletes)
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

// Check evaluates a permission for the caller's project and tenant.
func (s *Service) Check(ctx context.Context, p Principal, namespace, objectID, relation, subjectUserID string) (bool, error) {
	if namespace == "" || objectID == "" || relation == "" || subjectUserID == "" {
		return false, fmt.Errorf("%w: namespace, object_id, relation, subject_user_id are required", ErrInvalidArgument)
	}
	if suspended, err := s.resolver.suspended(ctx, p.ProjectID); err != nil {
		return false, err
	} else if suspended {
		return false, nil // a suspended project denies every check
	}
	return s.engine.Check(ctx, p.ProjectID, p.TenantID, namespace, objectID, relation, subjectUserID)
}

// Expand returns the userset tree for the caller's project and tenant.
func (s *Service) Expand(ctx context.Context, p Principal, namespace, objectID, relation string) (authz.Tree, error) {
	if namespace == "" || objectID == "" || relation == "" {
		return authz.Tree{}, fmt.Errorf("%w: namespace, object_id, relation are required", ErrInvalidArgument)
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return authz.Tree{}, err
	}
	return s.engine.Expand(ctx, p.ProjectID, p.TenantID, namespace, objectID, relation)
}

// ListObjects returns the object_ids in a namespace where subjectUserID has
// the relation, for the caller's project and tenant.
func (s *Service) ListObjects(ctx context.Context, p Principal, namespace, relation, subjectUserID string) ([]string, error) {
	if namespace == "" || relation == "" || subjectUserID == "" {
		return nil, fmt.Errorf("%w: namespace, relation, subject_user_id are required", ErrInvalidArgument)
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return nil, err
	}
	ids, err := s.engine.ListObjects(ctx, p.ProjectID, p.TenantID, namespace, relation, subjectUserID, s.maxListObjects)
	if errors.Is(err, authz.ErrTooManyObjects) {
		return nil, fmt.Errorf("%w: namespace has more than %d objects; narrow the query (pagination is a tracked follow-up)", ErrResourceExhausted, s.maxListObjects)
	}
	return ids, err
}

// DeprovisionUser deletes every relation tuple whose concrete subject is
// userID across all namespaces in the caller's project/tenant, returning the
// count removed. This is the clean revoke-everything path when a user leaves
// (it also reaches grants held via group usersets, which a per-subject tuple
// sweep on the concrete user would otherwise miss for group-derived access).
func (s *Service) DeprovisionUser(ctx context.Context, p Principal, userID string) (int, error) {
	if userID == "" {
		return 0, fmt.Errorf("%w: user_id is required", ErrInvalidArgument)
	}
	return s.repo.DeleteAllSubjectTuples(ctx, p.ProjectID, p.TenantID, userID)
}

func validateTuple(t authz.Tuple) error {
	if t.Namespace == "" || t.ObjectID == "" || t.Relation == "" {
		return fmt.Errorf("%w: tuple namespace, object_id, relation are required", ErrInvalidArgument)
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
	return nil
}
