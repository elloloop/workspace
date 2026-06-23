package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/pkg/authz"
)

// resolverTTL bounds how long a resolved project (model + status) is cached.
// Because invalidate() only reaches the local process, this TTL is what makes a
// model or suspension change converge across a horizontally-scaled fleet — a
// stale, possibly more-permissive model is served for at most this long.
const resolverTTL = 30 * time.Second

// resolverMaxEntries caps the cache so a caller sending many distinct (or
// non-existent) project_ids cannot grow process memory without bound.
const resolverMaxEntries = 4096

// sharedDefaultModel is the single DefaultModel instance returned for every
// unconfigured/unknown project, so resolving N distinct unknown project_ids
// does not allocate N full model maps. The engine only ever reads the model.
var sharedDefaultModel = authz.DefaultModel()

// resolved is a cached project resolution: its overlaid model (nil = the shared
// default), whether the project is suspended, and its pinned data region (empty
// = unpinned), with the time it was loaded.
type resolved struct {
	model      authz.Model
	suspended  bool
	dataRegion string
	// maxCheckReads is the project's per-request read-budget override: > 0
	// replaces the global GATEWAY_MAX_CHECK_READS for this project's
	// Check/CheckSet/Expand/ListObjects, 0 means use the fleet default.
	maxCheckReads int
	at            time.Time
}

func (e resolved) modelOrDefault() authz.Model {
	if e.model == nil {
		return sharedDefaultModel
	}
	return e.model
}

// modelResolver resolves a project's authorization model and status from the
// repository, caching the result with a TTL and a size cap. A project that does
// not exist, or that carries no model, resolves to the shared authz.DefaultModel
// — so an unconfigured project behaves exactly like the built-in defaults. A
// configured project's namespaces are OVERLAID onto the defaults per namespace:
// the product surface (workspace, group, resource) is always present, and a
// project adds its own namespaces (course, lesson, …) or overrides a default one
// by redeclaring it. The cache is invalidated immediately on the writing process
// when a project is created or updated, and self-heals elsewhere within the TTL.
type modelResolver struct {
	repo  Repository
	now   func() time.Time
	ttl   time.Duration
	max   int
	mu    sync.Mutex
	cache map[string]resolved
	// sf collapses concurrent cold-cache loads for the same project into a
	// single GetProject, preventing a resolver stampede on a hot project.
	sf singleflight.Group
}

func newModelResolver(repo Repository) *modelResolver {
	return &modelResolver{
		repo:  repo,
		now:   time.Now,
		ttl:   resolverTTL,
		max:   resolverMaxEntries,
		cache: map[string]resolved{},
	}
}

// resolve returns the cached resolution for projectID, loading and caching it on
// a miss or once the entry's TTL has elapsed. A single request resolves a
// project at most once — the suspended-check and the model load both go through
// here and share the entry — and concurrent cold-cache resolvers for the same
// project collapse to ONE store load via single-flight.
func (r *modelResolver) resolve(ctx context.Context, projectID string) (resolved, error) {
	if e, ok := r.lookup(projectID); ok {
		return e, nil
	}
	v, err, _ := r.sf.Do(projectID, func() (any, error) {
		// Re-check inside the flight: a racing caller may have just populated
		// the cache, so the winner of the flight does not reload needlessly.
		if e, ok := r.lookup(projectID); ok {
			return e, nil
		}
		e, err := r.load(ctx, projectID)
		if err != nil {
			return resolved{}, err
		}
		r.store(projectID, e)
		return e, nil
	})
	if err != nil {
		return resolved{}, err
	}
	return v.(resolved), nil
}

// ModelFor returns the authorization model for projectID.
func (r *modelResolver) ModelFor(ctx context.Context, projectID string) (authz.Model, error) {
	e, err := r.resolve(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return e.modelOrDefault(), nil
}

func (r *modelResolver) load(ctx context.Context, projectID string) (resolved, error) {
	p, err := r.repo.GetProject(ctx, projectID)
	switch {
	case errors.Is(err, ErrNotFound):
		return resolved{at: r.now()}, nil // nil model => shared default
	case err != nil:
		// Carry the projectID so a resolver/store failure on the Check hot path
		// is diagnosable rather than surfacing as an opaque CodeInternal.
		return resolved{}, fmt.Errorf("authz: resolve project %q: %w", projectID, err)
	}
	e := resolved{suspended: p.Status == ProjectSuspended, dataRegion: p.DataRegion, maxCheckReads: p.MaxCheckReads, at: r.now()}
	if len(p.Model) > 0 {
		// Overlay the project's namespaces onto a fresh copy of the defaults so
		// the built-in product surface survives a custom model; never mutate
		// sharedDefaultModel.
		m := authz.DefaultModel()
		for ns, rels := range p.Model {
			m[ns] = rels
		}
		e.model = m
	}
	return e, nil
}

func (r *modelResolver) lookup(projectID string) (resolved, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[projectID]
	if !ok {
		return resolved{}, false
	}
	if r.now().Sub(e.at) > r.ttl {
		delete(r.cache, projectID)
		return resolved{}, false
	}
	return e, true
}

func (r *modelResolver) store(projectID string, e resolved) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= r.max {
		r.evictLocked()
	}
	r.cache[projectID] = e
}

// evictLocked bounds the cache: it first drops every expired entry, then, if
// still at capacity, drops arbitrary entries until under the cap. The caller
// holds r.mu.
func (r *modelResolver) evictLocked() {
	now := r.now()
	for k, v := range r.cache {
		if now.Sub(v.at) > r.ttl {
			delete(r.cache, k)
		}
	}
	for k := range r.cache {
		if len(r.cache) < r.max {
			break
		}
		delete(r.cache, k)
	}
}

func (r *modelResolver) invalidate(projectID string) {
	r.mu.Lock()
	delete(r.cache, projectID)
	r.mu.Unlock()
}

// CreateProject registers a project and its (optional) authorization model.
// A nil model means the project uses the built-in default model. This is the
// configuration surface that lets two products (e.g. a kids platform and a
// professionals platform) run distinct models on one deployment.
func (s *Service) CreateProject(ctx context.Context, id, name string, model authz.Model, dataRegion string, maxCheckReads int) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	if HasControlChar(id) {
		return nil, fmt.Errorf("%w: project id must not contain control characters", ErrInvalidArgument)
	}
	if err := validateModel(model); err != nil {
		return nil, err
	}
	if err := ValidateRegion(dataRegion); err != nil {
		return nil, err
	}
	if err := ValidateMaxCheckReads(maxCheckReads); err != nil {
		return nil, err
	}
	now := s.now()
	p := &Project{
		ID:            id,
		Name:          name,
		Status:        ProjectActive,
		Model:         model,
		DataRegion:    dataRegion,
		MaxCheckReads: maxCheckReads,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.repo.CreateProject(ctx, p); err != nil {
		return nil, err
	}
	s.resolver.invalidate(id)
	if s.auditLog != nil {
		s.auditLog.LogAdminMutation(ctx, AdminAuditRecord{
			Action: AdminActionCreateProject, ProjectID: id, NewStatus: p.Status,
			StatusChanged: true, ModelChanged: len(model) > 0,
			RegionChanged: dataRegion != "", BudgetChanged: maxCheckReads > 0, At: now,
		})
	}
	return p, nil
}

// GetProject returns a project's configuration.
func (s *Service) GetProject(ctx context.Context, id string) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	return s.repo.GetProject(ctx, id)
}

// ListProjects returns every configured project.
func (s *Service) ListProjects(ctx context.Context) ([]*Project, error) {
	return s.repo.ListProjects(ctx)
}

// UpdateProject patches a project: it overwrites only the fields the caller
// actually provides, so e.g. suspending a project (status only) never wipes its
// custom model or name. An empty name and an empty/nil model both mean "leave
// unchanged", and an empty/unspecified status means "leave unchanged".
// (Resetting a model back to the default is not expressed through Update.)
func (s *Service) UpdateProject(ctx context.Context, id, name string, status ProjectStatus, model authz.Model, dataRegion string, clearRegion bool, maxCheckReads int, clearBudget bool) (*Project, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: project id is required", ErrInvalidArgument)
	}
	if HasControlChar(id) {
		return nil, fmt.Errorf("%w: project id must not contain control characters", ErrInvalidArgument)
	}
	if status != "" && status != ProjectActive && status != ProjectSuspended {
		return nil, fmt.Errorf("%w: status must be active or suspended", ErrInvalidArgument)
	}
	if err := validateModel(model); err != nil {
		return nil, err
	}
	if err := ValidateRegion(dataRegion); err != nil {
		return nil, err
	}
	if clearRegion && dataRegion != "" {
		return nil, fmt.Errorf("%w: set clear_data_region OR data_region, not both", ErrInvalidArgument)
	}
	if err := ValidateMaxCheckReads(maxCheckReads); err != nil {
		return nil, err
	}
	if clearBudget && maxCheckReads > 0 {
		return nil, fmt.Errorf("%w: set clear_max_check_reads OR max_check_reads, not both", ErrInvalidArgument)
	}
	p, err := s.repo.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	oldStatus, oldRegion, oldBudget := p.Status, p.DataRegion, p.MaxCheckReads
	if name != "" {
		p.Name = name
	}
	if status != "" {
		p.Status = status
	}
	if len(model) > 0 {
		p.Model = model
	}
	switch {
	case clearRegion:
		p.DataRegion = "" // explicit revert to region-agnostic
	case dataRegion != "":
		p.DataRegion = dataRegion
	}
	switch {
	case clearBudget:
		p.MaxCheckReads = 0 // explicit revert to the global default budget
	case maxCheckReads > 0:
		p.MaxCheckReads = maxCheckReads
	}
	// A repin to a region THIS instance does not serve would, after the resolver
	// TTL, make every request to the project fail closed fleet-wide — warn the
	// operator who triggered it (a hard check is impossible from one instance).
	if p.DataRegion != "" && s.dataRegion != "" && p.DataRegion != s.dataRegion {
		s.log.Warn("data_region_repin_unservable_here",
			zap.String("project_id", id),
			zap.String("target_region", p.DataRegion),
			zap.String("instance_region", s.dataRegion))
	}
	p.UpdatedAt = s.now()
	if err := s.repo.UpdateProject(ctx, p); err != nil {
		return nil, err
	}
	s.resolver.invalidate(id)
	if s.auditLog != nil {
		s.auditLog.LogAdminMutation(ctx, AdminAuditRecord{
			Action: AdminActionUpdateProject, ProjectID: id, NewStatus: p.Status,
			StatusChanged: status != "" && status != oldStatus,
			ModelChanged:  len(model) > 0,
			RegionChanged: p.DataRegion != oldRegion,
			BudgetChanged: p.MaxCheckReads != oldBudget, At: p.UpdatedAt,
		})
	}
	return p, nil
}

// EnsureDefaultProject idempotently seeds a project with the default model.
// It is called at boot for GATEWAY_DEFAULT_PROJECT_ID so the deployment's
// default shard is always resolvable, mirroring identity's bootstrap.
func (s *Service) EnsureDefaultProject(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	// Seed the default project REGION-AGNOSTIC (empty region), never auto-pinned
	// to the booting instance's region. The default shard is shared — it backs
	// every user's personal-workspace auto-provision — so auto-pinning it to
	// whichever instance booted first would deadlock every other region's
	// instances against one shared row. An agnostic default is servable by all.
	// An operator may still EXPLICITLY pin the default project, in which case the
	// fail-fast below correctly refuses to boot a mismatched instance.
	if existing, err := s.repo.GetProject(ctx, id); err == nil {
		if s.dataRegion != "" && existing.DataRegion != "" && existing.DataRegion != s.dataRegion {
			return fmt.Errorf("%w: default project %q is explicitly pinned to data region %q but this instance serves %q",
				ErrFailedPrecondition, id, existing.DataRegion, s.dataRegion)
		}
		return nil
	} else if !isNotFound(err) {
		return err
	}
	_, err := s.CreateProject(ctx, id, "Default", nil, "", 0) // region-agnostic, global budget; never auto-pinned
	if isAlreadyExists(err) {
		return nil // lost a race; the winner seeded it
	}
	return err
}

// maxDataRegionLen bounds a project's data-region identifier.
const maxDataRegionLen = 64

// validateRegion rejects a malformed data-region identifier. Empty is allowed
// (the project is unpinned). A region is a short token of lowercase letters,
// digits, '-' and '_' (e.g. "us-east-1", "eu_west").
func ValidateRegion(region string) error {
	if region == "" {
		return nil
	}
	if len(region) > maxDataRegionLen {
		return fmt.Errorf("%w: data region must be at most %d characters", ErrInvalidArgument, maxDataRegionLen)
	}
	for _, c := range region {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("%w: data region must be lowercase [a-z0-9_-]", ErrInvalidArgument)
		}
	}
	return nil
}

// regionServable reports a fail-closed error when this instance is pinned to a
// data region (GATEWAY_DATA_REGION) that differs from the project's pinned
// region — so a mis-routed request is refused rather than silently reading or
// writing data in the wrong region. When either side is empty the instance is
// region-agnostic and serves the project (today's behavior). Multi-region
// STORAGE routing is forward-compat; this is the enforcement half.
func (s *Service) regionServable(p Principal, res resolved) error {
	if s.dataRegion == "" || res.dataRegion == "" || res.dataRegion == s.dataRegion {
		return nil
	}
	// A structured breadcrumb so on-call can see an instance is refusing a
	// mis-routed project (paired with the authz_region_refused_total metric the
	// handler increments). %w keeps the wire code FailedPrecondition while
	// errors.Is(err, ErrRegionNotServable) distinguishes a residency refusal.
	s.log.Warn("data_region_refused",
		zap.String("project_id", p.ProjectID),
		zap.String("project_region", res.dataRegion),
		zap.String("instance_region", s.dataRegion))
	return fmt.Errorf("%w: project %q is pinned to data region %q; this instance serves %q",
		ErrRegionNotServable, p.ProjectID, res.dataRegion, s.dataRegion)
}

// ensureRegion resolves the project and applies the region guard. It is for
// repo-direct paths that do not otherwise resolve; a region-agnostic instance
// short-circuits with zero overhead (no resolve).
func (s *Service) ensureRegion(ctx context.Context, p Principal) error {
	if s.dataRegion == "" {
		return nil
	}
	res, err := s.resolver.resolve(ctx, p.ProjectID)
	if err != nil {
		return err
	}
	return s.regionServable(p, res)
}

// EnsureServable is the data-residency chokepoint enforced at the transport
// boundary: the connect handler calls it while building the Principal for EVERY
// project-scoped RPC (via acting/scope), so no read or write — management or
// data-plane — can touch a project whose pinned region differs from this
// instance's GATEWAY_DATA_REGION. A region-agnostic instance returns nil with
// zero overhead. (The data-plane methods also guard internally as defense in
// depth.)
func (s *Service) EnsureServable(ctx context.Context, p Principal) error {
	return s.ensureRegion(ctx, p)
}

// ValidateMaxCheckReads rejects a malformed per-project read-budget override. 0
// (or negative) is allowed and means "use the global GATEWAY_MAX_CHECK_READS
// default". A positive override must clear the SAME floor the global budget
// does (config.MinMaxCheckReads), so a small-positive typo (e.g. 5) is rejected
// rather than silently throttling the project's authz to a near-zero cap.
func ValidateMaxCheckReads(n int) error {
	if n > 0 && n < config.MinMaxCheckReads {
		return fmt.Errorf("%w: max_check_reads, when set, must be >= %d (use 0 for the global default)",
			ErrInvalidArgument, config.MinMaxCheckReads)
	}
	return nil
}

// validateModel round-trips the model through its JSON form to reject any
// structurally invalid rewrite before it is persisted.
func validateModel(m authz.Model) error {
	if len(m) == 0 {
		return nil
	}
	data, err := authz.MarshalModel(m)
	if err != nil {
		return fmt.Errorf("%w: model is not serializable: %w", ErrInvalidArgument, err)
	}
	if _, err := authz.ParseModel(data); err != nil {
		return fmt.Errorf("%w: invalid model: %w", ErrInvalidArgument, err)
	}
	if err := authz.ValidateModelRefs(m); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return nil
}
