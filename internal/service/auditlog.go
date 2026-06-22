package service

import (
	"context"
	"time"

	"github.com/elloloop/workspace/pkg/authz"
)

// TupleOpKind distinguishes a grant from a revocation in the tuple-change audit.
type TupleOpKind string

const (
	// TupleOpInsert is a grant (a tuple was written).
	TupleOpInsert TupleOpKind = "insert"
	// TupleOpDelete is a revocation (a tuple was removed).
	TupleOpDelete TupleOpKind = "delete"
)

// TupleChangeRecord is one relation-tuple grant or revocation, emitted to an
// AuditLogger after a successful WriteRelationTuples. It is append-only audit
// data and is never consulted on the authorization path.
type TupleChangeRecord struct {
	Op            TupleOpKind
	ProjectID     string
	TenantID      string
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
	SubjectSet    *authz.SubjectSet
	// Wildcard is true when the subject is the public wildcard (user:*).
	Wildcard bool
	// Caller is the calling-service identity that made the change (e.g. "slack"),
	// for attribution. Empty for an anonymous (flat-token) caller.
	Caller string
	At     time.Time
}

// AdminAction names an AdminService mutation.
type AdminAction string

const (
	// AdminActionCreateProject records a CreateProject mutation.
	AdminActionCreateProject AdminAction = "create_project"
	// AdminActionUpdateProject records an UpdateProject mutation.
	AdminActionUpdateProject AdminAction = "update_project"
)

// AdminAuditRecord is one administrative mutation to project configuration. It
// records WHAT changed (action, project, status, whether the model changed) but
// never the admin secret. The actor is the trusted admin-API caller; this
// service does not have an end-user identity for it.
type AdminAuditRecord struct {
	Action        AdminAction
	ProjectID     string
	NewStatus     ProjectStatus
	StatusChanged bool
	ModelChanged  bool
	// RegionChanged records a data-residency (data_region) pin/repin — a
	// compliance-critical mutation that must be attributable.
	RegionChanged bool
	// BudgetChanged records a per-project read-budget (max_check_reads)
	// override change — an operational/capacity knob that should be attributable.
	BudgetChanged bool
	At            time.Time
}

// AuditLogger receives append-only audit records for relation-tuple changes and
// admin mutations. Like DecisionLogger, an implementation MUST be non-blocking
// and MUST NOT affect the operation it audits (a logging failure never fails a
// write). A nil AuditLogger disables auditing with zero overhead.
type AuditLogger interface {
	LogTupleChange(ctx context.Context, rec TupleChangeRecord)
	LogAdminMutation(ctx context.Context, rec AdminAuditRecord)
}

// WithAuditLogger enables emitting an audit record for every relation-tuple
// change and admin mutation. Passing nil keeps auditing disabled.
func WithAuditLogger(l AuditLogger) Option {
	return func(s *Service) { s.auditLog = l }
}

// auditTupleChanges emits one TupleChangeRecord per inserted/deleted tuple after
// a successful write. Nil-guarded: zero cost when auditing is disabled.
func (s *Service) auditTupleChanges(ctx context.Context, p Principal, inserts, deletes []authz.Tuple) {
	if s.auditLog == nil {
		return
	}
	now := s.now()
	emit := func(op TupleOpKind, ts []authz.Tuple) {
		for _, t := range ts {
			rec := TupleChangeRecord{
				Op: op, ProjectID: p.ProjectID, TenantID: p.TenantID,
				Namespace: t.Namespace, ObjectID: t.ObjectID, Relation: t.Relation,
				SubjectUserID: t.Subject.UserID, SubjectSet: t.Subject.Set,
				Wildcard: t.Subject.Wildcard, Caller: p.Caller, At: now,
			}
			s.auditLog.LogTupleChange(ctx, rec)
		}
	}
	emit(TupleOpInsert, inserts)
	emit(TupleOpDelete, deletes)
}
