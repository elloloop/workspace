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
	// DeleteAllSubjectTuplesInProject deletes every tuple whose concrete subject
	// is userID, across all namespaces AND ALL TENANTS of the project, in one
	// transaction. It returns the count deleted. This is the storage primitive
	// behind user deprovisioning/erasure: a leaving or erased user must lose
	// access in every sibling tenant, not just one.
	DeleteAllSubjectTuplesInProject(ctx context.Context, projectID, userID string) (int, error)

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
	DeleteGroup(ctx context.Context, projectID, tenantID, id string) error
}

// TupleFilter selects stored tuples by exact match on its non-empty fields.
type TupleFilter struct {
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
}
