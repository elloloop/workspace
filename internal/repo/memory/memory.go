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

	projects    map[string]service.Project                              // id → project (global)
	workspaces  map[string]map[string]service.Workspace                 // scope → id → ws
	memberships map[string]map[string]map[string]service.Membership     // scope → ws → user → m
	invitations map[string]map[string]service.Invitation                // scope → id → inv
	groups      map[string]map[string]service.Group                     // scope → id → g
	enrollments map[string]map[string]map[string]service.Enrollment     // scope → group → memberKey → e
	seatLimits  map[string]map[string]int                               // scope → sku → limit
	seatAssigns map[string]map[string]map[string]service.SeatAssignment // scope → sku → user → a
	tuples      map[string]map[string]authz.Tuple                       // scope → tupleKey → tuple
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		projects:    map[string]service.Project{},
		workspaces:  map[string]map[string]service.Workspace{},
		memberships: map[string]map[string]map[string]service.Membership{},
		invitations: map[string]map[string]service.Invitation{},
		groups:      map[string]map[string]service.Group{},
		enrollments: map[string]map[string]map[string]service.Enrollment{},
		seatLimits:  map[string]map[string]int{},
		seatAssigns: map[string]map[string]map[string]service.SeatAssignment{},
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
	s.writeTuplesLocked(projectID, tenantID, inserts, deletes)
	return nil
}

// writeTuplesLocked applies tuple deletes then inserts. The caller holds s.mu.
func (s *Store) writeTuplesLocked(projectID, tenantID string, inserts, deletes []authz.Tuple) {
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

// tenantOfScope extracts the tenant from a "projectID\x00tenantID" scope key.
func tenantOfScope(sk string) string {
	if i := strings.IndexByte(sk, '\x00'); i >= 0 {
		return sk[i+1:]
	}
	return ""
}

func (s *Store) ListSubjectTuplesInProject(_ context.Context, projectID, userID string) ([]service.TupleAt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	prefix := projectID + "\x00"
	var out []service.TupleAt
	for sk, m := range s.tuples {
		if !strings.HasPrefix(sk, prefix) {
			continue
		}
		for _, t := range m {
			if t.Subject.Set == nil && !t.Subject.Wildcard && t.Subject.UserID == userID && t.ActiveAt(now) {
				out = append(out, service.TupleAt{TenantID: tenantOfScope(sk), Tuple: t})
			}
		}
	}
	sortTupleAt(out)
	return out, nil
}

func (s *Store) ListTuplesForSubjectSetsInProject(_ context.Context, projectID string, sets []authz.SubjectSet) ([]service.TupleAt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(sets) == 0 {
		return nil, nil
	}
	want := make(map[authz.SubjectSet]bool, len(sets))
	for _, st := range sets {
		want[st] = true
	}
	now := time.Now()
	prefix := projectID + "\x00"
	var out []service.TupleAt
	for sk, m := range s.tuples {
		if !strings.HasPrefix(sk, prefix) {
			continue
		}
		for _, t := range m {
			if t.Subject.Set != nil && want[*t.Subject.Set] && t.ActiveAt(now) {
				out = append(out, service.TupleAt{TenantID: tenantOfScope(sk), Tuple: t})
			}
		}
	}
	sortTupleAt(out)
	return out, nil
}

func sortTupleAt(ts []service.TupleAt) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].TenantID != ts[j].TenantID {
			return ts[i].TenantID < ts[j].TenantID
		}
		return tupleKey(ts[i].Tuple) < tupleKey(ts[j].Tuple)
	})
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
	s.putMembershipLocked(m)
	return nil
}

// putMembershipLocked upserts the membership row. The caller holds s.mu.
func (s *Store) putMembershipLocked(m *service.Membership) {
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
}

// PutMembershipAndTuples upserts the membership and applies the tuple writes
// atomically under a single lock.
func (s *Store) PutMembershipAndTuples(_ context.Context, m *service.Membership, inserts, deletes []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putMembershipLocked(m)
	s.writeTuplesLocked(m.ProjectID, m.TenantID, inserts, deletes)
	return nil
}

// DeleteMembershipAndTuples deletes the membership row and the given tuples
// atomically under a single lock; ErrNotFound leaves both untouched.
func (s *Store) DeleteMembershipAndTuples(_ context.Context, projectID, tenantID, workspaceID, userID string, deletes []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.deleteMembershipLocked(projectID, tenantID, workspaceID, userID); err != nil {
		return err
	}
	s.writeTuplesLocked(projectID, tenantID, nil, deletes)
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
	return s.deleteMembershipLocked(projectID, tenantID, workspaceID, userID)
}

// deleteMembershipLocked removes the membership row. The caller holds s.mu.
func (s *Store) deleteMembershipLocked(projectID, tenantID, workspaceID, userID string) error {
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
	delete(s.enrollments[sk], id)
	for k, t := range s.tuples[sk] {
		if t.Namespace == "group" && t.ObjectID == id {
			delete(s.tuples[sk], k)
		}
	}
	return nil
}

// ── enrollments ─────────────────────────────────────────────────────────────

func (s *Store) SetEnrollmentAndTuples(_ context.Context, e *service.Enrollment, inserts, deletes []authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(e.ProjectID, e.TenantID)
	byGroup := s.enrollments[sk]
	if byGroup == nil {
		byGroup = map[string]map[string]service.Enrollment{}
		s.enrollments[sk] = byGroup
	}
	byMember := byGroup[e.GroupID]
	if byMember == nil {
		byMember = map[string]service.Enrollment{}
		byGroup[e.GroupID] = byMember
	}
	kind, id := service.MemberKey(e.Member)
	byMember[kind+":"+id] = *e
	s.writeTuplesLocked(e.ProjectID, e.TenantID, inserts, deletes)
	return nil
}

func (s *Store) GetEnrollment(_ context.Context, projectID, tenantID, groupID string, member service.GroupMember) (*service.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kind, id := service.MemberKey(member)
	if e, ok := s.enrollments[scope(projectID, tenantID)][groupID][kind+":"+id]; ok {
		cp := e
		return &cp, nil
	}
	return nil, service.ErrNotFound
}

func (s *Store) ListEnrollments(_ context.Context, projectID, tenantID, groupID string) ([]*service.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.Enrollment
	for _, e := range s.enrollments[scope(projectID, tenantID)][groupID] {
		cp := e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			ki, ii := service.MemberKey(out[i].Member)
			kj, ij := service.MemberKey(out[j].Member)
			return ki+":"+ii < kj+":"+ij
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// ── seats (license/entitlement counting) ────────────────────────────────────

func (s *Store) SetSeatLimit(_ context.Context, projectID, tenantID, sku string, limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	if s.seatLimits[sk] == nil {
		s.seatLimits[sk] = map[string]int{}
	}
	s.seatLimits[sk][sku] = limit
	return nil
}

// seatUsageLocked returns the current count, the configured limit, and whether a
// limit is configured. The caller holds s.mu.
func (s *Store) seatUsageLocked(sk, sku string) (used, limit int, limited bool) {
	used = len(s.seatAssigns[sk][sku])
	limit, limited = s.seatLimits[sk][sku]
	return used, limit, limited
}

func (s *Store) GetSeatUsage(_ context.Context, projectID, tenantID, sku string) (service.SeatUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	used, limit, limited := s.seatUsageLocked(scope(projectID, tenantID), sku)
	return service.SeatUsage{SKU: sku, Used: used, Limit: limit, Limited: limited}, nil
}

func (s *Store) AssignSeatAndTuple(_ context.Context, a *service.SeatAssignment, tuple authz.Tuple) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(a.ProjectID, a.TenantID)
	if s.seatAssigns[sk] == nil {
		s.seatAssigns[sk] = map[string]map[string]service.SeatAssignment{}
	}
	if s.seatAssigns[sk][a.SKU] == nil {
		s.seatAssigns[sk][a.SKU] = map[string]service.SeatAssignment{}
	}
	// Idempotent: an already-seated user consumes no extra seat.
	if _, ok := s.seatAssigns[sk][a.SKU][a.UserID]; ok {
		return true, nil
	}
	if used, limit, limited := s.seatUsageLocked(sk, a.SKU); limited && used >= limit {
		return false, service.ErrResourceExhausted
	}
	s.seatAssigns[sk][a.SKU][a.UserID] = *a
	s.writeTuplesLocked(a.ProjectID, a.TenantID, []authz.Tuple{tuple}, nil)
	return false, nil
}

func (s *Store) RevokeSeatAndTuple(_ context.Context, projectID, tenantID, sku, userID string, tuple authz.Tuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := scope(projectID, tenantID)
	delete(s.seatAssigns[sk][sku], userID)
	s.writeTuplesLocked(projectID, tenantID, nil, []authz.Tuple{tuple})
	return nil
}

func (s *Store) ListSeats(_ context.Context, projectID, tenantID, sku string) ([]*service.SeatAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*service.SeatAssignment
	for _, a := range s.seatAssigns[scope(projectID, tenantID)][sku] {
		cp := a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AssignedAt.Equal(out[j].AssignedAt) {
			return out[i].UserID < out[j].UserID
		}
		return out[i].AssignedAt.Before(out[j].AssignedAt)
	})
	return out, nil
}
