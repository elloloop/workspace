package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// TupleOp is an insert or delete in a relation-tuple write.
type TupleOp struct {
	Delete bool
	Tuple  authz.Tuple
}

// WriteTuples applies raw relation-tuple writes for the caller's project.
// The caller is a trusted product backend holding a verified token; writes
// are scoped to its project (the isolation shard) and validated for shape.
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
	return s.repo.WriteTuples(ctx, p.ProjectID, inserts, deletes)
}

// ReadTuples returns stored tuples in the caller's project matching f.
func (s *Service) ReadTuples(ctx context.Context, p Principal, f TupleFilter) ([]authz.Tuple, error) {
	return s.repo.ReadTuples(ctx, p.ProjectID, f)
}

// Check evaluates a permission for the caller's project.
func (s *Service) Check(ctx context.Context, p Principal, namespace, objectID, relation, subjectUserID string) (bool, error) {
	if namespace == "" || objectID == "" || relation == "" || subjectUserID == "" {
		return false, fmt.Errorf("%w: namespace, object_id, relation, subject_user_id are required", ErrInvalidArgument)
	}
	return s.engine.Check(ctx, p.ProjectID, namespace, objectID, relation, subjectUserID)
}

// Expand returns the userset tree for the caller's project.
func (s *Service) Expand(ctx context.Context, p Principal, namespace, objectID, relation string) (authz.Tree, error) {
	if namespace == "" || objectID == "" || relation == "" {
		return authz.Tree{}, fmt.Errorf("%w: namespace, object_id, relation are required", ErrInvalidArgument)
	}
	return s.engine.Expand(ctx, p.ProjectID, namespace, objectID, relation)
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
