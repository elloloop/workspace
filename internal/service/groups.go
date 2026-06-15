package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspaces/pkg/authz"
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
	return s.repo.GetGroup(ctx, p.ProjectID, id)
}

func (s *Service) ListGroups(ctx context.Context, p Principal, workspaceID string) ([]*Group, error) {
	if workspaceID != "" {
		if _, err := s.requireWorkspace(ctx, p, workspaceID, RoleGuest); err != nil {
			return nil, err
		}
	}
	return s.repo.ListGroups(ctx, p.ProjectID, workspaceID)
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
	g, err := s.repo.GetGroup(ctx, p.ProjectID, id)
	if err != nil {
		return err
	}
	if err := s.requireGroupManager(ctx, p, g); err != nil {
		return err
	}
	return s.repo.DeleteGroup(ctx, p.ProjectID, id)
}

func (s *Service) AddGroupMember(ctx context.Context, p Principal, groupID string, member GroupMember) error {
	g, err := s.repo.GetGroup(ctx, p.ProjectID, groupID)
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
	return s.repo.WriteTuples(ctx, p.ProjectID, []authz.Tuple{t}, nil)
}

func (s *Service) RemoveGroupMember(ctx context.Context, p Principal, groupID string, member GroupMember) error {
	g, err := s.repo.GetGroup(ctx, p.ProjectID, groupID)
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
	return s.repo.WriteTuples(ctx, p.ProjectID, nil, []authz.Tuple{t})
}

func (s *Service) ListGroupMembers(ctx context.Context, p Principal, groupID string) ([]GroupMember, error) {
	if _, err := s.repo.GetGroup(ctx, p.ProjectID, groupID); err != nil {
		return nil, err
	}
	subjects, err := s.repo.ListSubjects(ctx, p.ProjectID, "group", groupID, "member")
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
