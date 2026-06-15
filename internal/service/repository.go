package service

import (
	"context"

	"github.com/elloloop/workspace/pkg/authz"
)

// Repository is the storage boundary. Every method is scoped to a project
// (the isolation shard, identity ADR-0002). All drivers (memory, postgres)
// must satisfy internal/repo/conformance identically — same uniqueness,
// ordering, and not-found semantics.
//
// It embeds authz.TupleReader so the same store backs both the product
// entities and the relation-tuple engine.
type Repository interface {
	authz.TupleReader

	// ── Relation tuples ──────────────────────────────────────────────
	// WriteTuples applies deletes then inserts atomically. Inserting an
	// existing tuple is idempotent; deleting a missing tuple is a no-op.
	WriteTuples(ctx context.Context, projectID string, inserts, deletes []authz.Tuple) error
	// ReadTuples returns stored tuples matching the non-empty filter fields.
	ReadTuples(ctx context.Context, projectID string, f TupleFilter) ([]authz.Tuple, error)

	// ── Workspaces ───────────────────────────────────────────────────
	CreateWorkspace(ctx context.Context, w *Workspace) error
	GetWorkspace(ctx context.Context, projectID, id string) (*Workspace, error)
	UpdateWorkspace(ctx context.Context, w *Workspace) error
	DeleteWorkspace(ctx context.Context, projectID, id string) error
	// PersonalWorkspace returns the user's personal workspace, or ErrNotFound.
	PersonalWorkspace(ctx context.Context, projectID, userID string) (*Workspace, error)
	// WorkspacesForUser returns every workspace the user is an active member
	// of, ordered by creation time.
	WorkspacesForUser(ctx context.Context, projectID, userID string) ([]*Workspace, error)

	// ── Memberships ──────────────────────────────────────────────────
	PutMembership(ctx context.Context, m *Membership) error
	GetMembership(ctx context.Context, projectID, workspaceID, userID string) (*Membership, error)
	ListMembers(ctx context.Context, projectID, workspaceID string) ([]*Membership, error)
	DeleteMembership(ctx context.Context, projectID, workspaceID, userID string) error

	// ── Invitations ──────────────────────────────────────────────────
	CreateInvitation(ctx context.Context, inv *Invitation) error
	GetInvitation(ctx context.Context, projectID, id string) (*Invitation, error)
	GetInvitationByTokenHash(ctx context.Context, projectID, tokenHash string) (*Invitation, error)
	UpdateInvitation(ctx context.Context, inv *Invitation) error
	ListInvitations(ctx context.Context, projectID, workspaceID string) ([]*Invitation, error)

	// ── Groups ───────────────────────────────────────────────────────
	CreateGroup(ctx context.Context, g *Group) error
	GetGroup(ctx context.Context, projectID, id string) (*Group, error)
	// ListGroups returns groups in the project; when workspaceID is non-empty
	// it restricts to groups owned by that workspace.
	ListGroups(ctx context.Context, projectID, workspaceID string) ([]*Group, error)
	DeleteGroup(ctx context.Context, projectID, id string) error
}

// TupleFilter selects stored tuples by exact match on its non-empty fields.
type TupleFilter struct {
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
}
