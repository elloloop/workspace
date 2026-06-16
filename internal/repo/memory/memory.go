// Package memory is the in-memory Repository driver. It is the default
// backend for tests and single-process deployments, and the reference
// implementation the conformance suite pins every other driver against.
package memory

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// Store is a goroutine-safe in-memory Repository. Product data is keyed by the
// (project, tenant) scope; projects themselves are global configuration.
type Store struct {
	mu sync.RWMutex

	projects    map[string]service.Project                          // id → project (global)
	workspaces  map[string]map[string]service.Workspace             // scope → id → ws
	memberships map[string]map[string]map[string]service.Membership // scope → ws → user → m
	invitations map[string]map[string]service.Invitation            // scope → id → inv
	groups      map[string]map[string]service.Group                 // scope → id → g
	tuples      map[string]map[string]authz.Tuple                   // scope → tupleKey → tuple
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		projects:    map[string]service.Project{},
		workspaces:  map[string]map[string]service.Workspace{},
		memberships: map[string]map[string]map[string]service.Membership{},
		invitations: map[string]map[string]service.Invitation{},
		groups:      map[string]map[string]service.Group{},
		tuples:      map[string]map[string]authz.Tuple{},
	}
}

var _ service.Repository = (*Store)(nil)

// scope is the data-isolation key: a project and a tenant within it. The null
// byte cannot appear in an id, so it is an unambiguous separator.
func scope(projectID, tenantID string) string { return projectID + "\x00" + tenantID }

// ── tuple keys ────────────────────────────────────────────────────────────

func subjectKey(s authz.Subject) string {
	switch {
	case s.Wildcard:
		return "w:*"
	case s.Set != nil:
		return "s:" + s.Set.Namespace + "/" + s.Set.ObjectID + "/" + s.Set.Relation
	default:
		return "u:" + s.UserID
	}
}

func tupleKey(t authz.Tuple) string {
	return t.Namespace + "|" + t.ObjectID + "|" + t.Relation + "|" + subjectKey(t.Subject)
}

// ── projects ──────────────────────────────────────────────────────────────

func (s *Store) CreateProject(_ context.Context, p *service.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[p.ID]; ok {
		return service.ErrAlreadyExists
	}
	s.projects[p.ID] = *p
	return nil
}

func (s *Store) GetProject(_ context.Context, id string) (*service.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.projects[id]; ok {
		cp := p
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) UpdateProject(_ context.Context, p *service.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.projects[p.ID]; !ok {
		return service.ErrNotFound
	}
	s.projects[p.ID] = *p
	return nil
}

func (s *Store) ListProjects(_ context.Context) ([]*service.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*service.Project, 0, len(s.projects))
	for _, p := range s.projects {
		cp := p
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

// ── relation tuples ───────────────────────────────────────────────────────

func (s *Store) WriteTuples(_ context.Context, projectID, tenantID string, inserts, deletes []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	m := s.tuples[sk]
	if m == nil {
		m = map[string]authz.Tuple{}
		s.tuples[sk] = m
	}
	for _, t := range deletes {
		delete(m, tupleKey(t))
	}
	for _, t := range inserts {
		m[tupleKey(t)] = t
	}
	return nil
}

func (s *Store) ListSubjects(_ context.Context, projectID, tenantID, namespace, objectID, relation string) ([]authz.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []authz.Subject
	for _, t := range s.tuples[scope(projectID, tenantID)] {
		if t.Namespace == namespace && t.ObjectID == objectID && t.Relation == relation && t.ActiveAt(now) {
			out = append(out, t.Subject)
		}
	}
	return out, nil
}

func (s *Store) ListObjectIDs(_ context.Context, projectID, tenantID, namespace string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	seen := map[string]bool{}
	var out []string
	for _, t := range s.tuples[scope(projectID, tenantID)] {
		if t.Namespace == namespace && t.ActiveAt(now) && !seen[t.ObjectID] {
			seen[t.ObjectID] = true
			out = append(out, t.ObjectID)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) ReadTuples(_ context.Context, projectID, tenantID string, f service.TupleFilter) ([]authz.Tuple, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var out []authz.Tuple
	for _, t := range s.tuples[scope(projectID, tenantID)] {
		if !t.ActiveAt(now) {
			continue
		}
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

func (s *Store) DeleteAllSubjectTuplesInProject(_ context.Context, projectID, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := projectID + "\x00" // every (project, tenant) scope for this project
	n := 0
	for sk, m := range s.tuples {
		if !strings.HasPrefix(sk, prefix) {
			continue
		}
		for k, t := range m {
			if t.Subject.Set == nil && !t.Subject.Wildcard && t.Subject.UserID == userID {
				delete(m, k)
				n++
			}
		}
	}
	return n, nil
}

// ── workspaces ────────────────────────────────────────────────────────────

func (s *Store) CreateWorkspace(_ context.Context, w *service.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(w.ProjectID, w.TenantID)
	byID := s.workspaces[sk]
	if byID == nil {
		byID = map[string]service.Workspace{}
		s.workspaces[sk] = byID
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

func (s *Store) GetWorkspace(_ context.Context, projectID, tenantID, id string) (*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if w, ok := s.workspaces[scope(projectID, tenantID)][id]; ok {
		cp := w
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) UpdateWorkspace(_ context.Context, w *service.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(w.ProjectID, w.TenantID)
	if _, ok := s.workspaces[sk][w.ID]; !ok {
		return service.ErrNotFound
	}
	s.workspaces[sk][w.ID] = *w
	return nil
}

func (s *Store) DeleteWorkspace(_ context.Context, projectID, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	if _, ok := s.workspaces[sk][id]; !ok {
		return service.ErrNotFound
	}
	delete(s.workspaces[sk], id)
	delete(s.memberships[sk], id)
	for k, t := range s.tuples[sk] {
		if t.Namespace == "workspace" && t.ObjectID == id {
			delete(s.tuples[sk], k)
		}
	}
	for k, inv := range s.invitations[sk] {
		if inv.WorkspaceID == id {
			delete(s.invitations[sk], k)
		}
	}
	return nil
}

func (s *Store) PersonalWorkspace(_ context.Context, projectID, tenantID, userID string) (*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, w := range s.workspaces[scope(projectID, tenantID)] {
		if w.Type == service.TypePersonal && w.OwnerUserID == userID {
			cp := w
			return &cp, nil
		}
	}
	return nil, service.ErrNotFound
}

func (s *Store) WorkspacesForUser(_ context.Context, projectID, tenantID, userID string) ([]*service.Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sk := scope(projectID, tenantID)
	var out []*service.Workspace
	for wsID, byUser := range s.memberships[sk] {
		m, ok := byUser[userID]
		if !ok || m.Status != service.StatusActive {
			continue
		}
		if w, ok := s.workspaces[sk][wsID]; ok {
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
	sk := scope(m.ProjectID, m.TenantID)
	byWs := s.memberships[sk]
	if byWs == nil {
		byWs = map[string]map[string]service.Membership{}
		s.memberships[sk] = byWs
	}
	byUser := byWs[m.WorkspaceID]
	if byUser == nil {
		byUser = map[string]service.Membership{}
		byWs[m.WorkspaceID] = byUser
	}
	byUser[m.UserID] = *m
	return nil
}

func (s *Store) GetMembership(_ context.Context, projectID, tenantID, workspaceID, userID string) (*service.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.memberships[scope(projectID, tenantID)][workspaceID][userID]; ok {
		cp := m
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) ListMembers(_ context.Context, projectID, tenantID, workspaceID string) ([]*service.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Membership
	for _, m := range s.memberships[scope(projectID, tenantID)][workspaceID] {
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

func (s *Store) DeleteMembership(_ context.Context, projectID, tenantID, workspaceID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	if _, ok := s.memberships[sk][workspaceID][userID]; !ok {
		return service.ErrNotFound
	}
	delete(s.memberships[sk][workspaceID], userID)
	return nil
}

// ── invitations ───────────────────────────────────────────────────────────

func (s *Store) CreateInvitation(_ context.Context, inv *service.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(inv.ProjectID, inv.TenantID)
	byID := s.invitations[sk]
	if byID == nil {
		byID = map[string]service.Invitation{}
		s.invitations[sk] = byID
	}
	if _, ok := byID[inv.ID]; ok {
		return service.ErrAlreadyExists
	}
	byID[inv.ID] = *inv
	return nil
}

func (s *Store) GetInvitation(_ context.Context, projectID, tenantID, id string) (*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if inv, ok := s.invitations[scope(projectID, tenantID)][id]; ok {
		cp := inv
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) GetInvitationByTokenHash(_ context.Context, projectID, tenantID, tokenHash string) (*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.invitations[scope(projectID, tenantID)] {
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
	sk := scope(inv.ProjectID, inv.TenantID)
	if _, ok := s.invitations[sk][inv.ID]; !ok {
		return service.ErrNotFound
	}
	s.invitations[sk][inv.ID] = *inv
	return nil
}

func (s *Store) ListInvitations(_ context.Context, projectID, tenantID, workspaceID string) ([]*service.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Invitation
	for _, inv := range s.invitations[scope(projectID, tenantID)] {
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
	sk := scope(g.ProjectID, g.TenantID)
	byID := s.groups[sk]
	if byID == nil {
		byID = map[string]service.Group{}
		s.groups[sk] = byID
	}
	if _, ok := byID[g.ID]; ok {
		return service.ErrAlreadyExists
	}
	byID[g.ID] = *g
	return nil
}

func (s *Store) GetGroup(_ context.Context, projectID, tenantID, id string) (*service.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if g, ok := s.groups[scope(projectID, tenantID)][id]; ok {
		cp := g
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) ListGroups(_ context.Context, projectID, tenantID, workspaceID string) ([]*service.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Group
	for _, g := range s.groups[scope(projectID, tenantID)] {
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

func (s *Store) DeleteGroup(_ context.Context, projectID, tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	if _, ok := s.groups[sk][id]; !ok {
		return service.ErrNotFound
	}
	delete(s.groups[sk], id)
	for k, t := range s.tuples[sk] {
		if t.Namespace == "group" && t.ObjectID == id {
			delete(s.tuples[sk], k)
		}
	}
	return nil
}
