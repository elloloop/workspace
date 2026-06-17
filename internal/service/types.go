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
	ID     string
	Name   string
	Status ProjectStatus
	Model  authz.Model // nil ⇒ DefaultModel
	// DataRegion, when set, pins the project's data to a region/storage target.
	// An instance configured with GATEWAY_DATA_REGION serves only projects whose
	// region matches (or is unset); a mismatch fails closed. Empty ⇒ unpinned.
	DataRegion string
	CreatedAt  time.Time
	UpdatedAt  time.Time
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

// EnrollmentState is a member's lifecycle state within a group used as a
// cohort/class. Only the access-bearing states (Enrolled, Active) put the
// member in the group's `member` userset; the rest are tracked without access.
type EnrollmentState string

const (
	EnrollmentWaitlisted EnrollmentState = "waitlisted"
	EnrollmentEnrolled   EnrollmentState = "enrolled"
	EnrollmentActive     EnrollmentState = "active"
	EnrollmentCompleted  EnrollmentState = "completed"
	EnrollmentDropped    EnrollmentState = "dropped"
)

// Valid reports whether s is a known enrollment state.
func (s EnrollmentState) Valid() bool {
	switch s {
	case EnrollmentWaitlisted, EnrollmentEnrolled, EnrollmentActive, EnrollmentCompleted, EnrollmentDropped:
		return true
	}
	return false
}

// GrantsAccess reports whether s places the member in the group's `member`
// userset (the backing group#member tuple is present). Enrolled and Active
// grant; Waitlisted, Completed, and Dropped do not.
func (s EnrollmentState) GrantsAccess() bool {
	return s == EnrollmentEnrolled || s == EnrollmentActive
}

// Enrollment is a member's tracked lifecycle state within a group (cohort).
type Enrollment struct {
	ProjectID string
	TenantID  string
	GroupID   string
	Member    GroupMember
	State     EnrollmentState
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SeatAssignment is one user's consumed seat for a sku, scoped to a
// (project, tenant). Each assignment is backed by a `seat:<sku>#holder@user`
// relation tuple so Check can gate access on seat-holding.
type SeatAssignment struct {
	ProjectID  string
	TenantID   string
	SKU        string
	UserID     string
	AssignedAt time.Time
}

// SeatUsage reports a sku's seat consumption against its configured cap.
// Limited is false when no limit is configured for the sku (unlimited).
type SeatUsage struct {
	SKU     string
	Used    int
	Limit   int
	Limited bool
}

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
