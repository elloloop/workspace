// Package service holds the workspace service's domain types, the storage
// Repository boundary, and the business logic that maps the product surface
// (workspaces, groups, invitations) onto Zanzibar relation tuples.
package service

import (
	"time"

	"github.com/elloloop/workspace/pkg/authz"
)

// ProjectStatus controls whether a project is resolvable. A suspended project
// is rejected at resolution, mirroring identity.
type ProjectStatus string

const (
	ProjectActive    ProjectStatus = "active"
	ProjectSuspended ProjectStatus = "suspended"
)

// Project is the configuration/model boundary (identity ADR-0002). Each
// project carries its own authorization model; a nil Model falls back to
// authz.DefaultModel, so an unconfigured project behaves exactly like the
// built-in defaults. Tenants live within a project as the data-isolation
// boundary and are addressed by tenant_id on every scoped call (no separate
// row is required for the default tenant).
type Project struct {
	ID        string
	Name      string
	Status    ProjectStatus
	Model     authz.Model // nil ⇒ DefaultModel
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Role is a workspace membership grade. It is also the relation name written
// into the `workspace` authz namespace, so the two never drift.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"
)

// Valid reports whether r is one of the known grades.
func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleGuest:
		return true
	}
	return false
}

// WorkspaceType distinguishes the auto-provisioned personal workspace from
// user-created team workspaces.
type WorkspaceType string

const (
	TypePersonal WorkspaceType = "personal"
	TypeTeam     WorkspaceType = "team"
)

// MembershipStatus tracks a member's lifecycle within a workspace.
type MembershipStatus string

const (
	StatusActive    MembershipStatus = "active"
	StatusInvited   MembershipStatus = "invited"
	StatusSuspended MembershipStatus = "suspended"
)

// InvitationStatus tracks a pending invite's lifecycle.
type InvitationStatus string

const (
	InvitePending  InvitationStatus = "pending"
	InviteAccepted InvitationStatus = "accepted"
	InviteRevoked  InvitationStatus = "revoked"
	InviteExpired  InvitationStatus = "expired"
)

type Workspace struct {
	ID          string
	ProjectID   string
	TenantID    string
	Slug        string
	DisplayName string
	Type        WorkspaceType
	OwnerUserID string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Membership struct {
	ProjectID   string
	TenantID    string
	WorkspaceID string
	UserID      string
	Role        Role
	Status      MembershipStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Invitation struct {
	ID          string
	ProjectID   string
	TenantID    string
	WorkspaceID string
	Email       string
	Role        Role
	Status      InvitationStatus
	InvitedBy   string
	// TokenHash is the SHA-256 of the invite token; the plaintext token is
	// returned once from CreateInvitation and never stored.
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Group struct {
	ID          string
	ProjectID   string
	TenantID    string
	WorkspaceID string // optional owning workspace; "" for standalone groups
	Slug        string
	DisplayName string
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
