package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// GroupMember is a user or a nested group.
type GroupMember struct {
	UserID  string
	GroupID string
}

// CreateGroup creates a group. When workspaceID is set the caller must be a
// member of that workspace; standalone groups (workspaceID == "") may be
// created by any authenticated user.
func (s *Service) CreateGroup(ctx context.Context, p Principal, displayName, slug, workspaceID string) (*Group, error) {
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return nil, err
	}
	displayName = trimName(displayName)
	if displayName == "" {
		return nil, fmt.Errorf("%w: display_name is required", ErrInvalidArgument)
	}
	if workspaceID != "" {
		if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleMember); err != nil {
			return nil, err
		}
	}
	if slug == "" {
		slug = slugify(displayName)
	} else {
		slug = slugify(slug)
	}
	now := s.now()
	g := &Group{
		ID:          s.newID(),
		ProjectID:   p.ProjectID,
		TenantID:    p.TenantID,
		WorkspaceID: workspaceID,
		Slug:        slug,
		DisplayName: displayName,
		CreatedBy:   p.UserID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.repo.CreateGroup(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Service) GetGroup(ctx context.Context, p Principal, id string) (*Group, error) {
	return s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, id)
}

func (s *Service) ListGroups(ctx context.Context, p Principal, workspaceID string) ([]*Group, error) {
	if workspaceID != "" {
		if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleGuest); err != nil {
			return nil, err
		}
	}
	return s.repo.ListGroups(ctx, p.ProjectID, p.TenantID, workspaceID)
}

// requireGroupManager confirms the caller may mutate the group: its creator,
// or an admin of its owning workspace.
func (s *Service) requireGroupManager(ctx context.Context, p Principal, g *Group) error {
	if g.CreatedBy == p.UserID {
		return nil
	}
	if g.WorkspaceID != "" {
		ok, err := s.allowed(ctx, p, g.WorkspaceID, RoleAdmin)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("%w: requires group creator or workspace admin", ErrPermissionDenied)
}

func (s *Service) DeleteGroup(ctx context.Context, p Principal, id string) error {
	g, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return err
	}
	return s.repo.DeleteGroup(ctx, p.ProjectID, p.TenantID, id)
}

func (s *Service) AddGroupMember(ctx context.Context, p Principal, groupID string, member GroupMember) error {
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return err
	}
	g, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, groupID)
	if err != nil {
		return err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return err
	}
	t, err := groupMemberTuple(groupID, member)
	if err != nil {
		return err
	}
	return s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, []authz.Tuple{t}, nil)
}

func (s *Service) RemoveGroupMember(ctx context.Context, p Principal, groupID string, member GroupMember) error {
	g, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, groupID)
	if err != nil {
		return err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return err
	}
	t, err := groupMemberTuple(groupID, member)
	if err != nil {
		return err
	}
	return s.repo.WriteTuples(ctx, p.ProjectID, p.TenantID, nil, []authz.Tuple{t})
}

func (s *Service) ListGroupMembers(ctx context.Context, p Principal, groupID string) ([]GroupMember, error) {
	if _, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, groupID); err != nil {
		return nil, err
	}
	subjects, err := s.repo.ListSubjects(ctx, p.ProjectID, p.TenantID, "group", groupID, "member")
	if err != nil {
		return nil, err
	}
	out := make([]GroupMember, 0, len(subjects))
	for _, sub := range subjects {
		if sub.Set == nil {
			out = append(out, GroupMember{UserID: sub.UserID})
		} else if sub.Set.Namespace == "group" {
			out = append(out, GroupMember{GroupID: sub.Set.ObjectID})
		}
	}
	return out, nil
}

// SetEnrollmentState upserts a member's enrollment state in a group (cohort) and
// moves the backing `group:<id>#member` tuple atomically: present iff the new
// state grants access (Enrolled/Active), absent otherwise (Waitlisted/
// Completed/Dropped). Access is thus revoked/granted purely by tuple presence,
// so Check/CheckSet over the group's `member` userset naturally exclude a
// completed, dropped, or waitlisted enrollee. Requires the group manager.
func (s *Service) SetEnrollmentState(ctx context.Context, p Principal, groupID string, member GroupMember, state EnrollmentState) (*Enrollment, error) {
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return nil, err
	}
	if !state.Valid() {
		return nil, fmt.Errorf("%w: unknown enrollment state %q", ErrInvalidArgument, state)
	}
	t, err := groupMemberTuple(groupID, member) // also validates the member shape
	if err != nil {
		return nil, err
	}
	g, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, groupID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return nil, err
	}

	now := s.now()
	e := &Enrollment{
		ProjectID: p.ProjectID, TenantID: p.TenantID, GroupID: groupID,
		Member: member, State: state, CreatedAt: now, UpdatedAt: now,
	}
	// Preserve the original CreatedAt across transitions.
	if existing, gerr := s.repo.GetEnrollment(ctx, p.ProjectID, p.TenantID, groupID, member); gerr == nil {
		e.CreatedAt = existing.CreatedAt
	} else if !isNotFound(gerr) {
		return nil, gerr
	}

	// The backing member tuple is present iff the state grants access.
	var inserts, deletes []authz.Tuple
	if state.GrantsAccess() {
		inserts = []authz.Tuple{t}
	} else {
		deletes = []authz.Tuple{t}
	}
	if err := s.repo.SetEnrollmentAndTuples(ctx, e, inserts, deletes); err != nil {
		return nil, err
	}
	return e, nil
}

// ListEnrollments returns a group's tracked enrollments. Requires the group
// manager (its creator or a workspace admin for a workspace-owned group).
func (s *Service) ListEnrollments(ctx context.Context, p Principal, groupID string) ([]*Enrollment, error) {
	g, err := s.repo.GetGroup(ctx, p.ProjectID, p.TenantID, groupID)
	if err != nil {
		return nil, err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return nil, err
	}
	return s.repo.ListEnrollments(ctx, p.ProjectID, p.TenantID, groupID)
}

// groupMemberTuple builds the `group:<id>#member@subject` tuple for a user
// or a nested group userset.
func groupMemberTuple(groupID string, m GroupMember) (authz.Tuple, error) {
	switch {
	case m.UserID != "" && m.GroupID == "":
		return userTuple("group", groupID, "member", m.UserID), nil
	case m.GroupID != "" && m.UserID == "":
		return authz.Tuple{
			Namespace: "group", ObjectID: groupID, Relation: "member",
			Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "group", ObjectID: m.GroupID, Relation: "member"}},
		}, nil
	default:
		return authz.Tuple{}, fmt.Errorf("%w: member must be exactly one of user_id or group_id", ErrInvalidArgument)
	}
}

// MemberKey returns a stable (kind, id) pair for a group member, where kind is
// "user" or "group". It is the storage key for enrollment rows.
func MemberKey(m GroupMember) (kind, id string) {
	if m.GroupID != "" {
		return "group", m.GroupID
	}
	return "user", m.UserID
}

// MemberFromKey is the inverse of MemberKey, reconstructing a GroupMember from
// a stored (kind, id) pair.
func MemberFromKey(kind, id string) GroupMember {
	if kind == "group" {
		return GroupMember{GroupID: id}
	}
	return GroupMember{UserID: id}
}
