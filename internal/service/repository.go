package service

import (
	"context"

	"github.com/elloloop/workspace/pkg/authz"
)

// Repository is the storage boundary. Every method is scoped to a project (the
// configuration/model shard, identity ADR-0002) and a tenant (the data
// isolation shard within a project). All drivers (memory, postgres) must
// satisfy internal/repo/conformance identically — same uniqueness, ordering,
// and not-found semantics. An empty tenantID is the project's default tenant.
//
// It embeds authz.TupleReader (and authz.ObjectLister) so the same store backs
// both the product entities and the relation-tuple engine.
type Repository interface {
	authz.TupleReader
	authz.ObjectLister

	// ── Relation tuples ──────────────────────────────────────────────
	// WriteTuples applies deletes then inserts atomically. Inserting an
	// existing tuple is idempotent; deleting a missing tuple is a no-op.
	WriteTuples(ctx context.Context, projectID, tenantID string, inserts, deletes []authz.Tuple) error
	// ReadTuples returns stored tuples matching the non-empty filter fields.
	ReadTuples(ctx context.Context, projectID, tenantID string, f TupleFilter) ([]authz.Tuple, error)
	// ConsistencyToken returns the current monotonic write sequence for a
	// (project, tenant) shard — the value a WriteTuples reaches and that a read
	// carrying a consistency token is checked against. It only ever increases
	// (per shard) and is 0 for a shard that has never been written.
	ConsistencyToken(ctx context.Context, projectID, tenantID string) (int64, error)
	// DeleteAllSubjectTuplesInProject deletes every tuple whose concrete subject
	// is userID, across all namespaces AND ALL TENANTS of the project, in one
	// transaction. It returns the count deleted. This is the storage primitive
	// behind user deprovisioning/erasure: a leaving or erased user must lose
	// access in every sibling tenant, not just one.
	DeleteAllSubjectTuplesInProject(ctx context.Context, projectID, userID string) (int, error)
	// ListSubjectTuplesInProject returns every tuple whose concrete subject is
	// userID, across all namespaces AND all tenants of the project — the read
	// sibling of DeleteAllSubjectTuplesInProject, backing subject data export.
	// Expired tuples are excluded.
	ListSubjectTuplesInProject(ctx context.Context, projectID, userID string) ([]TupleAt, error)
	// ListTuplesForSubjectSetsInProject returns every tuple whose subject is one
	// of the given usersets, across all tenants of the project (one level of
	// group-mediated grant resolution for export). Expired tuples are excluded.
	ListTuplesForSubjectSetsInProject(ctx context.Context, projectID string, sets []authz.SubjectSet) ([]TupleAt, error)

	// ── Projects ─────────────────────────────────────────────────────
	// Projects are the configuration/model boundary. A project carries its
	// own authorization model; an absent project falls back to the default.
	CreateProject(ctx context.Context, p *Project) error
	GetProject(ctx context.Context, id string) (*Project, error)
	UpdateProject(ctx context.Context, p *Project) error
	ListProjects(ctx context.Context) ([]*Project, error)

	// ── Workspaces ───────────────────────────────────────────────────
	CreateWorkspace(ctx context.Context, w *Workspace) error
	GetWorkspace(ctx context.Context, projectID, tenantID, id string) (*Workspace, error)
	UpdateWorkspace(ctx context.Context, w *Workspace) error
	DeleteWorkspace(ctx context.Context, projectID, tenantID, id string) error
	// PersonalWorkspace returns the user's personal workspace, or ErrNotFound.
	PersonalWorkspace(ctx context.Context, projectID, tenantID, userID string) (*Workspace, error)
	// WorkspacesForUser returns every workspace the user is an active member
	// of, ordered by creation time.
	WorkspacesForUser(ctx context.Context, projectID, tenantID, userID string) ([]*Workspace, error)

	// ── Memberships ──────────────────────────────────────────────────
	PutMembership(ctx context.Context, m *Membership) error
	GetMembership(ctx context.Context, projectID, tenantID, workspaceID, userID string) (*Membership, error)
	ListMembers(ctx context.Context, projectID, tenantID, workspaceID string) ([]*Membership, error)
	DeleteMembership(ctx context.Context, projectID, tenantID, workspaceID, userID string) error
	// PutMembershipAndTuples upserts the membership row and applies the tuple
	// writes (deletes then inserts, scoped to m's project/tenant) in ONE
	// transaction, so a membership and its backing authz role tuple can never
	// diverge on a crash between the two writes.
	PutMembershipAndTuples(ctx context.Context, m *Membership, inserts, deletes []authz.Tuple) error
	// DeleteMembershipAndTuples deletes the membership row and the given tuples
	// in ONE transaction. Returns ErrNotFound (rolling back) if the membership
	// is absent.
	DeleteMembershipAndTuples(ctx context.Context, projectID, tenantID, workspaceID, userID string, deletes []authz.Tuple) error

	// ── Invitations ──────────────────────────────────────────────────
	CreateInvitation(ctx context.Context, inv *Invitation) error
	GetInvitation(ctx context.Context, projectID, tenantID, id string) (*Invitation, error)
	GetInvitationByTokenHash(ctx context.Context, projectID, tenantID, tokenHash string) (*Invitation, error)
	UpdateInvitation(ctx context.Context, inv *Invitation) error
	ListInvitations(ctx context.Context, projectID, tenantID, workspaceID string) ([]*Invitation, error)

	// ── Groups ───────────────────────────────────────────────────────
	CreateGroup(ctx context.Context, g *Group) error
	GetGroup(ctx context.Context, projectID, tenantID, id string) (*Group, error)
	// ListGroups returns groups in the project/tenant; when workspaceID is
	// non-empty it restricts to groups owned by that workspace.
	ListGroups(ctx context.Context, projectID, tenantID, workspaceID string) ([]*Group, error)
	// DeleteGroup removes the group, its member tuples, AND its enrollment rows.
	DeleteGroup(ctx context.Context, projectID, tenantID, id string) error

	// ── Enrollments (group lifecycle overlay) ────────────────────────
	// SetEnrollmentAndTuples upserts the enrollment row and applies the tuple
	// writes (deletes then inserts, scoped to e's project/tenant) in ONE
	// transaction, so the enrollment state and its backing group#member tuple
	// can never diverge on a crash between the two writes.
	SetEnrollmentAndTuples(ctx context.Context, e *Enrollment, inserts, deletes []authz.Tuple) error
	// GetEnrollment returns the enrollment for a (group, member), or ErrNotFound.
	GetEnrollment(ctx context.Context, projectID, tenantID, groupID string, member GroupMember) (*Enrollment, error)
	// ListEnrollments returns a group's enrollments, ordered by creation time.
	ListEnrollments(ctx context.Context, projectID, tenantID, groupID string) ([]*Enrollment, error)

	// ── Seats (license/entitlement counting) ─────────────────────────
	// SetSeatLimit configures the cap for a (project, tenant, sku); a non-nil
	// limit must be >= 0 (0 admits none). A NIL limit CLEARS the cap (deletes the
	// row), returning the sku to unlimited.
	SetSeatLimit(ctx context.Context, projectID, tenantID, sku string, limit *int) error
	// GetSeatUsage returns the seat consumption and configured cap for a sku.
	GetSeatUsage(ctx context.Context, projectID, tenantID, sku string) (SeatUsage, error)
	// AssignSeatAndTuple atomically enforces the sku's cap and, on success,
	// inserts the assignment AND its backing tuple in ONE transaction — so the
	// count check and the insert cannot race, and concurrent assigns can never
	// oversubscribe. Returns alreadyHeld=true (a no-op) when the user already
	// has a seat, and ErrResourceExhausted when the cap is reached.
	AssignSeatAndTuple(ctx context.Context, a *SeatAssignment, tuple authz.Tuple) (alreadyHeld bool, err error)
	// RevokeSeatAndTuple frees a user's seat and deletes its backing tuple in
	// one transaction; revoking an absent seat is a no-op.
	RevokeSeatAndTuple(ctx context.Context, projectID, tenantID, sku, userID string, tuple authz.Tuple) error
	// ListSeats returns the assignments for a sku, ordered by assignment time.
	ListSeats(ctx context.Context, projectID, tenantID, sku string) ([]*SeatAssignment, error)
}

// TupleAt is a stored relation tuple together with the tenant it lives in.
type TupleAt struct {
	TenantID string
	Tuple    authz.Tuple
}

// TupleFilter selects stored tuples by exact match on its non-empty fields.
type TupleFilter struct {
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
}
