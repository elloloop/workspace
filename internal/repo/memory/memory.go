// Package memory is the in-memory Repository driver. It is the default
// backend for tests and single-process deployments, and the reference
// implementation the conformance suite pins every other driver against.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/elloloop/workspaces/internal/service"
	"github.com/elloloop/workspaces/pkg/authz"
)

// Store is a goroutine-safe in-memory Repository.
type Store struct {
	mu sync.RWMutex

	workspaces  map[string]map[string]service.Workspace             // project → id → ws
	memberships map[string]map[string]map[string]service.Membership // project → ws → user → m
	invitations map[string]map[string]service.Invitation            // project → id → inv
	groups      map[string]map[string]service.Group                 // project → id → g
	tuples      map[string]map[string]authz.Tuple                   // project → tupleKey → tuple
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		workspaces:  map[string]map[string]service.Workspace{},
		memberships: map[string]map[string]map[string]service.Membership{},
		invitations: map[string]map[string]service.Invitation{},
		groups:      map[string]map[string]service.Group{},
		tuples:      map[string]map[string]authz.Tuple{},
	}
}

var _ service.Repository = (*Store)(nil)

// ── tuple keys ────────────────────────────────────────────────────────────

func subjectKey(s authz.Subject) string {
	if s.Set != nil {
		return "s:" + s.Set.Namespace + "/" + s.Set.ObjectID + "/" + s.Set.Relation
	}
	return "u:" + s.UserID
}

func tupleKey(t authz.Tuple) string {
	return t.Namespace + "|" + t.ObjectID + "|" + t.Relation + "|" + subjectKey(t.Subject)
}

// ── relation tuples ───────────────────────────────────────────────────────

func (s *Store) WriteTuples(_ context.Context, projectID string, inserts, deletes []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.tuples[projectID]
	if m == nil {
		m = map[string]authz.Tuple{}
		s.tuples[projectID] = m
	}
	for _, t := range deletes {
		delete(m, tupleKey(t))
	}
	for _, t := range inserts {
		m[tupleKey(t)] = t
	}
	return nil
}

func (s *Store) ListSubjects(_ context.Context, projectID, namespace, objectID, relation string) ([]authz.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authz.Subject
	for _, t := range s.tuples[projectID] {
		if t.Namespace == namespace && t.ObjectID == objectID && t.Relation == relation {
			out = append(out, t.Subject)
		}
	}
	return out, nil
}

func (s *Store) ReadTuples(_ context.Context, projectID string, f service.TupleFilter) ([]authz.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authz.Tuple
	for _, t := range s.tuples[projectID] {
		if f.Namespace != "" && t.Namespace != f.Namespace {
			continue
		}
		if f.ObjectID != "" && t.ObjectID != f.ObjectID {
			continue
		}
		if f.Relation != "" && t.Relation != f.Relation {
			continue
		}
		if f.SubjectUserID != "" && t.Subject.UserID != f.SubjectUserID {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return tupleKey(out[i]) < tupleKey(out[j]) })
	return out, nil
}

// ── workspaces ────────────────────────────────────────────────────────────

func (s *Store) CreateWorkspace(_ context.Context, w *service.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := s.workspaces[w.ProjectID]
	if byID == nil {
		byID = map[string]service.Workspace{}
		s.workspaces[w.ProjectID] = byID
	}
	if _, ok := byID[w.ID]; ok {
		return service.ErrAlreadyExists
	}
	if w.Type == service.TypePersonal {
		for _, ex := range byID {
			if ex.Type == service.TypePersonal && ex.OwnerUserID == w.OwnerUserID {
				return service.ErrAlreadyExists
			}
		}
	}
	byID[w.ID] = *w
	return nil
}

func (s *Store) GetWorkspace(_ context.Context, projectID, id string) (*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w, ok := s.workspaces[projectID][id]; ok {
		cp := w
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) UpdateWorkspace(_ context.Context, w *service.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workspaces[w.ProjectID][w.ID]; !ok {
		return service.ErrNotFound
	}
	s.workspaces[w.ProjectID][w.ID] = *w
	return nil
}

func (s *Store) DeleteWorkspace(_ context.Context, projectID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workspaces[projectID][id]; !ok {
		return service.ErrNotFound
	}
	delete(s.workspaces[projectID], id)
	delete(s.memberships[projectID], id)
	for k, t := range s.tuples[projectID] {
		if t.Namespace == "workspace" && t.ObjectID == id {
			delete(s.tuples[projectID], k)
		}
	}
	for k, inv := range s.invitations[projectID] {
		if inv.WorkspaceID == id {
			delete(s.invitations[projectID], k)
		}
	}
	return nil
}

func (s *Store) PersonalWorkspace(_ context.Context, projectID, userID string) (*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, w := range s.workspaces[projectID] {
		if w.Type == service.TypePersonal && w.OwnerUserID == userID {
			cp := w
			return &cp, nil
		}
	}
	return nil, service.ErrNotFound
}

func (s *Store) WorkspacesForUser(_ context.Context, projectID, userID string) ([]*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Workspace
	for wsID, byUser := range s.memberships[projectID] {
		m, ok := byUser[userID]
		if !ok || m.Status != service.StatusActive {
			continue
		}
		if w, ok := s.workspaces[projectID][wsID]; ok {
			cp := w
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// ── memberships ───────────────────────────────────────────────────────────

func (s *Store) PutMembership(_ context.Context, m *service.Membership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byWs := s.memberships[m.ProjectID]
	if byWs == nil {
		byWs = map[string]map[string]service.Membership{}
		s.memberships[m.ProjectID] = byWs
	}
	byUser := byWs[m.WorkspaceID]
	if byUser == nil {
		byUser = map[string]service.Membership{}
		byWs[m.WorkspaceID] = byUser
	}
	byUser[m.UserID] = *m
	return nil
}

func (s *Store) GetMembership(_ context.Context, projectID, workspaceID, userID string) (*service.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.memberships[projectID][workspaceID][userID]; ok {
		cp := m
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) ListMembers(_ context.Context, projectID, workspaceID string) ([]*service.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Membership
	for _, m := range s.memberships[projectID][workspaceID] {
		cp := m
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].UserID < out[j].UserID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) DeleteMembership(_ context.Context, projectID, workspaceID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.memberships[projectID][workspaceID][userID]; !ok {
		return service.ErrNotFound
	}
	delete(s.memberships[projectID][workspaceID], userID)
	return nil
}

// ── invitations ───────────────────────────────────────────────────────────

func (s *Store) CreateInvitation(_ context.Context, inv *service.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := s.invitations[inv.ProjectID]
	if byID == nil {
		byID = map[string]service.Invitation{}
		s.invitations[inv.ProjectID] = byID
	}
	if _, ok := byID[inv.ID]; ok {
		return service.ErrAlreadyExists
	}
	byID[inv.ID] = *inv
	return nil
}

func (s *Store) GetInvitation(_ context.Context, projectID, id string) (*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if inv, ok := s.invitations[projectID][id]; ok {
		cp := inv
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) GetInvitationByTokenHash(_ context.Context, projectID, tokenHash string) (*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.invitations[projectID] {
		if inv.TokenHash == tokenHash {
			cp := inv
			return &cp, nil
		}
	}
	return nil, service.ErrNotFound
}

func (s *Store) UpdateInvitation(_ context.Context, inv *service.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.invitations[inv.ProjectID][inv.ID]; !ok {
		return service.ErrNotFound
	}
	s.invitations[inv.ProjectID][inv.ID] = *inv
	return nil
}

func (s *Store) ListInvitations(_ context.Context, projectID, workspaceID string) ([]*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Invitation
	for _, inv := range s.invitations[projectID] {
		if inv.WorkspaceID == workspaceID {
			cp := inv
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// ── groups ────────────────────────────────────────────────────────────────

func (s *Store) CreateGroup(_ context.Context, g *service.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := s.groups[g.ProjectID]
	if byID == nil {
		byID = map[string]service.Group{}
		s.groups[g.ProjectID] = byID
	}
	if _, ok := byID[g.ID]; ok {
		return service.ErrAlreadyExists
	}
	byID[g.ID] = *g
	return nil
}

func (s *Store) GetGroup(_ context.Context, projectID, id string) (*service.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if g, ok := s.groups[projectID][id]; ok {
		cp := g
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) ListGroups(_ context.Context, projectID, workspaceID string) ([]*service.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Group
	for _, g := range s.groups[projectID] {
		if workspaceID != "" && g.WorkspaceID != workspaceID {
			continue
		}
		cp := g
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (s *Store) DeleteGroup(_ context.Context, projectID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[projectID][id]; !ok {
		return service.ErrNotFound
	}
	delete(s.groups[projectID], id)
	for k, t := range s.tuples[projectID] {
		if t.Namespace == "group" && t.ObjectID == id {
			delete(s.tuples[projectID], k)
		}
	}
	return nil
}
