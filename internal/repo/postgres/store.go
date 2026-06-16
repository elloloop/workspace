// Package postgres is the Postgres Repository driver. It satisfies
// service.Repository (and thus authz.TupleReader) over a pgxpool, matching
// the in-memory reference driver's semantics exactly. Product tables are
// sharded by (project_id, tenant_id) (identity ADR-0002): project_id is the
// configuration/model boundary, tenant_id the data-isolation boundary within
// it, and both lead every primary key, index, and WHERE clause. Projects
// themselves are global configuration.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is a Postgres-backed Repository.
type Store struct {
	pool *pgxpool.Pool
}

var _ service.Repository = (*Store)(nil)

// Open opens a pgxpool against dsn and pings it.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Pool exposes the underlying pool (used by tests to truncate between runs).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

const schemaSQL = `
CREATE TABLE IF NOT EXISTS projects (
	id           text        NOT NULL,
	name         text        NOT NULL DEFAULT '',
	status       text        NOT NULL DEFAULT 'active',
	config_json  jsonb       NOT NULL DEFAULT '{}'::jsonb,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS workspaces (
	project_id     text        NOT NULL,
	tenant_id      text        NOT NULL DEFAULT '',
	id             text        NOT NULL,
	slug           text        NOT NULL,
	display_name   text        NOT NULL,
	type           text        NOT NULL,
	owner_user_id  text        NOT NULL,
	created_at     timestamptz NOT NULL,
	updated_at     timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, id)
);
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS memberships (
	project_id   text        NOT NULL,
	tenant_id    text        NOT NULL DEFAULT '',
	workspace_id text        NOT NULL,
	user_id      text        NOT NULL,
	role         text        NOT NULL,
	status       text        NOT NULL,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, workspace_id, user_id)
);
ALTER TABLE memberships ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS invitations (
	project_id   text        NOT NULL,
	tenant_id    text        NOT NULL DEFAULT '',
	id           text        NOT NULL,
	workspace_id text        NOT NULL,
	email        text        NOT NULL,
	role         text        NOT NULL,
	status       text        NOT NULL,
	invited_by   text        NOT NULL,
	token_hash   text        NOT NULL,
	created_at   timestamptz NOT NULL,
	expires_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, id)
);
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS invitations_token_idx
	ON invitations (project_id, tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS invitations_workspace_idx
	ON invitations (project_id, tenant_id, workspace_id);

CREATE TABLE IF NOT EXISTS groups (
	project_id   text        NOT NULL,
	tenant_id    text        NOT NULL DEFAULT '',
	id           text        NOT NULL,
	workspace_id text        NOT NULL,
	slug         text        NOT NULL,
	display_name text        NOT NULL,
	created_by   text        NOT NULL,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, id)
);
ALTER TABLE groups ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS groups_workspace_idx
	ON groups (project_id, tenant_id, workspace_id);

CREATE TABLE IF NOT EXISTS relation_tuples (
	project_id        text NOT NULL,
	tenant_id         text NOT NULL DEFAULT '',
	namespace         text NOT NULL,
	object_id         text NOT NULL,
	relation          text NOT NULL,
	subject_kind      text NOT NULL,
	subject_user_id   text NOT NULL DEFAULT '',
	subject_namespace text NOT NULL DEFAULT '',
	subject_object_id text NOT NULL DEFAULT '',
	subject_relation  text NOT NULL DEFAULT '',
	PRIMARY KEY (project_id, tenant_id, namespace, object_id, relation, subject_kind,
		subject_user_id, subject_namespace, subject_object_id, subject_relation)
);
ALTER TABLE relation_tuples ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';

-- ── Upgrade-path key migrations ──────────────────────────────────────────
-- The composite (project_id, tenant_id, …) primary keys above only take effect
-- inside CREATE TABLE IF NOT EXISTS, which is a no-op on a pre-existing table.
-- These guarded blocks widen the keys on already-populated databases so tenant
-- isolation actually holds and ON CONFLICT targets resolve. Each rebuilds ONLY
-- when tenant_id is not yet part of the key, so Migrate stays idempotent and
-- never rebuilds a large index on a healthy boot. The old key is always a
-- strict prefix of the new one, so no existing row can violate the wider key.
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		WHERE i.indrelid='workspaces'::regclass AND i.indisprimary AND a.attname='tenant_id') THEN
		ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_pkey;
		ALTER TABLE workspaces ADD PRIMARY KEY (project_id, tenant_id, id);
	END IF;
END $$;
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		WHERE i.indrelid='memberships'::regclass AND i.indisprimary AND a.attname='tenant_id') THEN
		ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_pkey;
		ALTER TABLE memberships ADD PRIMARY KEY (project_id, tenant_id, workspace_id, user_id);
	END IF;
END $$;
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		WHERE i.indrelid='invitations'::regclass AND i.indisprimary AND a.attname='tenant_id') THEN
		ALTER TABLE invitations DROP CONSTRAINT IF EXISTS invitations_pkey;
		ALTER TABLE invitations ADD PRIMARY KEY (project_id, tenant_id, id);
	END IF;
END $$;
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		WHERE i.indrelid='groups'::regclass AND i.indisprimary AND a.attname='tenant_id') THEN
		ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_pkey;
		ALTER TABLE groups ADD PRIMARY KEY (project_id, tenant_id, id);
	END IF;
END $$;
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		WHERE i.indrelid='relation_tuples'::regclass AND i.indisprimary AND a.attname='tenant_id') THEN
		ALTER TABLE relation_tuples DROP CONSTRAINT IF EXISTS relation_tuples_pkey;
		ALTER TABLE relation_tuples ADD PRIMARY KEY (project_id, tenant_id, namespace, object_id, relation,
			subject_kind, subject_user_id, subject_namespace, subject_object_id, subject_relation);
	END IF;
END $$;
-- Drop a stale personal-workspace unique index (old (project_id, owner_user_id)
-- definition) so the tenant-scoped one below actually replaces it; CREATE … IF
-- NOT EXISTS alone would skip an index that already exists under this name.
DO $$ BEGIN
	IF EXISTS (SELECT 1 FROM pg_class WHERE relname='workspaces_personal_uniq' AND relkind='i') THEN
		IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
			WHERE i.indexrelid='workspaces_personal_uniq'::regclass AND a.attname='tenant_id') THEN
			DROP INDEX workspaces_personal_uniq;
		END IF;
	END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_personal_uniq
	ON workspaces (project_id, tenant_id, owner_user_id)
	WHERE type = 'personal';
-- Supports DeleteAllSubjectTuples and subject-only ReadTuples without a
-- full (project, tenant) partition scan.
CREATE INDEX IF NOT EXISTS relation_tuples_subject_user_idx
	ON relation_tuples (project_id, tenant_id, subject_user_id)
	WHERE subject_kind = 'user';
`

const (
	// migrateAdvisoryLockKey serializes Migrate across replicas: only one
	// process runs the (idempotent) DDL at a time, so concurrent boots cannot
	// race the primary-key rebuilds. Any fixed app-unique key works.
	migrateAdvisoryLockKey int64 = 0x6D696772 // "migr"
	// migrateLockTimeout bounds how long a single migration statement waits for
	// its table lock before failing fast, so a contended hot-path table is not
	// stalled indefinitely by an auto-migration on boot.
	migrateLockTimeout = "5s"
)

// Migrate creates/upgrades the schema. It is idempotent and safe to run on every
// boot: a session advisory lock serializes concurrent replicas, and lock_timeout
// makes a contended DDL fail fast instead of stalling the data plane. NOTE: on a
// LARGE populated table the primary-key rebuild still takes heavy (ACCESS
// EXCLUSIVE) locks while it runs — for that deploy prefer running `workspace
// migrate` out of band with GATEWAY_POSTGRES_AUTO_MIGRATE=false.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Transaction-scoped advisory lock: serializes migrators across replicas and
	// auto-releases on commit/rollback (no leak onto a pooled connection). It
	// blocks only against other migrators, never against live queries.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	// Fail fast rather than stall the authz data plane if a DDL can't get its
	// table lock (e.g. a long-running query holds it). SET LOCAL is scoped to tx.
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '"+migrateLockTimeout+"'"); err != nil {
		return fmt.Errorf("set lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, schemaSQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isUniqueViolation reports whether err is a Postgres unique_violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ── projects ──────────────────────────────────────────────────────────────

// projectConfig is the JSON envelope persisted in projects.config_json. The
// model is optional; an absent model means the project uses the default model.
type projectConfig struct {
	Model json.RawMessage `json:"model,omitempty"`
}

func encodeProjectConfig(m authz.Model) (string, error) {
	cfg := projectConfig{}
	if len(m) > 0 {
		raw, err := authz.MarshalModel(m)
		if err != nil {
			return "", err
		}
		cfg.Model = raw
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeProjectConfig(blob string) (authz.Model, error) {
	if blob == "" {
		return nil, nil
	}
	var cfg projectConfig
	if err := json.Unmarshal([]byte(blob), &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Model) == 0 {
		return nil, nil
	}
	return authz.ParseModel(cfg.Model)
}

func (s *Store) CreateProject(ctx context.Context, p *service.Project) error {
	cfg, err := encodeProjectConfig(p.Model)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO projects (id, name, status, config_json, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		p.ID, p.Name, string(p.Status), cfg, p.CreatedAt, p.UpdatedAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanProject(row pgx.Row) (*service.Project, error) {
	var p service.Project
	var status, cfg string
	err := row.Scan(&p.ID, &p.Name, &status, &cfg, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Status = service.ProjectStatus(status)
	model, err := decodeProjectConfig(cfg)
	if err != nil {
		return nil, err
	}
	p.Model = model
	return &p, nil
}

const projectCols = `id, name, status, config_json, created_at, updated_at`

func (s *Store) GetProject(ctx context.Context, id string) (*service.Project, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id=$1`, id)
	return scanProject(row)
}

func (s *Store) UpdateProject(ctx context.Context, p *service.Project) error {
	cfg, err := encodeProjectConfig(p.Model)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE projects SET name=$2, status=$3, config_json=$4, updated_at=$5 WHERE id=$1`,
		p.ID, p.Name, string(p.Status), cfg, p.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (s *Store) ListProjects(ctx context.Context) ([]*service.Project, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+projectCols+` FROM projects ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── relation tuples ─────────────────────────────────────────────────────────

func tupleCols(t authz.Tuple) (kind, userID, ns, objID, rel string) {
	switch {
	case t.Subject.Wildcard:
		return "wildcard", "", "", "", ""
	case t.Subject.Set != nil:
		return "set", "", t.Subject.Set.Namespace, t.Subject.Set.ObjectID, t.Subject.Set.Relation
	default:
		return "user", t.Subject.UserID, "", "", ""
	}
}

func (s *Store) WriteTuples(ctx context.Context, projectID, tenantID string, inserts, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, t := range deletes {
		kind, uid, sns, soid, srel := tupleCols(t)
		_, err := tx.Exec(ctx,
			`DELETE FROM relation_tuples WHERE project_id=$1 AND tenant_id=$2 AND namespace=$3 AND object_id=$4
			   AND relation=$5 AND subject_kind=$6 AND subject_user_id=$7
			   AND subject_namespace=$8 AND subject_object_id=$9 AND subject_relation=$10`,
			projectID, tenantID, t.Namespace, t.ObjectID, t.Relation, kind, uid, sns, soid, srel)
		if err != nil {
			return err
		}
	}
	for _, t := range inserts {
		kind, uid, sns, soid, srel := tupleCols(t)
		_, err := tx.Exec(ctx,
			`INSERT INTO relation_tuples
			   (project_id, tenant_id, namespace, object_id, relation, subject_kind,
			    subject_user_id, subject_namespace, subject_object_id, subject_relation)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
			projectID, tenantID, t.Namespace, t.ObjectID, t.Relation, kind, uid, sns, soid, srel)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func scanTuple(row pgx.Row) (authz.Tuple, error) {
	var t authz.Tuple
	var kind, uid, sns, soid, srel string
	if err := row.Scan(&t.Namespace, &t.ObjectID, &t.Relation, &kind, &uid, &sns, &soid, &srel); err != nil {
		return t, err
	}
	switch kind {
	case "set":
		t.Subject.Set = &authz.SubjectSet{Namespace: sns, ObjectID: soid, Relation: srel}
	case "wildcard":
		t.Subject.Wildcard = true
	default:
		t.Subject.UserID = uid
	}
	return t, nil
}

func (s *Store) ListSubjects(ctx context.Context, projectID, tenantID, namespace, objectID, relation string) ([]authz.Subject, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT namespace, object_id, relation, subject_kind, subject_user_id,
		        subject_namespace, subject_object_id, subject_relation
		   FROM relation_tuples
		  WHERE project_id=$1 AND tenant_id=$2 AND namespace=$3 AND object_id=$4 AND relation=$5`,
		projectID, tenantID, namespace, objectID, relation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authz.Subject
	for rows.Next() {
		t, err := scanTuple(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t.Subject)
	}
	return out, rows.Err()
}

func (s *Store) ListObjectIDs(ctx context.Context, projectID, tenantID, namespace string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT object_id FROM relation_tuples
		  WHERE project_id=$1 AND tenant_id=$2 AND namespace=$3
		  ORDER BY object_id`,
		projectID, tenantID, namespace)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) ReadTuples(ctx context.Context, projectID, tenantID string, f service.TupleFilter) ([]authz.Tuple, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT namespace, object_id, relation, subject_kind, subject_user_id,
		        subject_namespace, subject_object_id, subject_relation
		   FROM relation_tuples
		  WHERE project_id=$1 AND tenant_id=$2
		    AND ($3='' OR namespace=$3)
		    AND ($4='' OR object_id=$4)
		    AND ($5='' OR relation=$5)
		    AND ($6='' OR subject_user_id=$6)
		  ORDER BY namespace, object_id, relation, subject_kind, subject_user_id,
		           subject_namespace, subject_object_id, subject_relation`,
		projectID, tenantID, f.Namespace, f.ObjectID, f.Relation, f.SubjectUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authz.Tuple
	for rows.Next() {
		t, err := scanTuple(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAllSubjectTuplesInProject(ctx context.Context, projectID, userID string) (int, error) {
	// Project-wide erase across ALL tenants. project_id leads the
	// relation_tuples_subject_user_idx index, so dropping the tenant_id filter
	// still uses it.
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM relation_tuples
		  WHERE project_id=$1 AND subject_kind='user' AND subject_user_id=$2`,
		projectID, userID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ── workspaces ──────────────────────────────────────────────────────────────

func (s *Store) CreateWorkspace(ctx context.Context, w *service.Workspace) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO workspaces
		   (project_id, tenant_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		w.ProjectID, w.TenantID, w.ID, w.Slug, w.DisplayName, string(w.Type), w.OwnerUserID, w.CreatedAt, w.UpdatedAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanWorkspace(row pgx.Row) (*service.Workspace, error) {
	var w service.Workspace
	var typ string
	err := row.Scan(&w.ProjectID, &w.TenantID, &w.ID, &w.Slug, &w.DisplayName, &typ, &w.OwnerUserID, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	w.Type = service.WorkspaceType(typ)
	return &w, nil
}

const workspaceCols = `project_id, tenant_id, id, slug, display_name, type, owner_user_id, created_at, updated_at`

func (s *Store) GetWorkspace(ctx context.Context, projectID, tenantID, id string) (*service.Workspace, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+workspaceCols+` FROM workspaces WHERE project_id=$1 AND tenant_id=$2 AND id=$3`, projectID, tenantID, id)
	return scanWorkspace(row)
}

func (s *Store) UpdateWorkspace(ctx context.Context, w *service.Workspace) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE workspaces SET slug=$4, display_name=$5, type=$6, owner_user_id=$7,
		        created_at=$8, updated_at=$9
		  WHERE project_id=$1 AND tenant_id=$2 AND id=$3`,
		w.ProjectID, w.TenantID, w.ID, w.Slug, w.DisplayName, string(w.Type), w.OwnerUserID, w.CreatedAt, w.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteWorkspace(ctx context.Context, projectID, tenantID, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `DELETE FROM workspaces WHERE project_id=$1 AND tenant_id=$2 AND id=$3`, projectID, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3`, projectID, tenantID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM invitations WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3`, projectID, tenantID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM relation_tuples WHERE project_id=$1 AND tenant_id=$2 AND namespace='workspace' AND object_id=$3`,
		projectID, tenantID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PersonalWorkspace(ctx context.Context, projectID, tenantID, userID string) (*service.Workspace, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+workspaceCols+` FROM workspaces
		  WHERE project_id=$1 AND tenant_id=$2 AND owner_user_id=$3 AND type='personal'`, projectID, tenantID, userID)
	return scanWorkspace(row)
}

func (s *Store) WorkspacesForUser(ctx context.Context, projectID, tenantID, userID string) ([]*service.Workspace, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT w.project_id, w.tenant_id, w.id, w.slug, w.display_name, w.type, w.owner_user_id,
		        w.created_at, w.updated_at
		   FROM workspaces w
		   JOIN memberships m
		     ON m.project_id=w.project_id AND m.tenant_id=w.tenant_id AND m.workspace_id=w.id
		  WHERE w.project_id=$1 AND w.tenant_id=$2 AND m.user_id=$3 AND m.status='active'
		  ORDER BY w.created_at, w.id`,
		projectID, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Workspace
	for rows.Next() {
		w, err := scanWorkspace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ── memberships ─────────────────────────────────────────────────────────────

func (s *Store) PutMembership(ctx context.Context, m *service.Membership) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO memberships
		   (project_id, tenant_id, workspace_id, user_id, role, status, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (project_id, tenant_id, workspace_id, user_id) DO UPDATE
		   SET role=EXCLUDED.role, status=EXCLUDED.status,
		       created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at`,
		m.ProjectID, m.TenantID, m.WorkspaceID, m.UserID, string(m.Role), string(m.Status), m.CreatedAt, m.UpdatedAt)
	return err
}

func scanMembership(row pgx.Row) (*service.Membership, error) {
	var m service.Membership
	var role, status string
	err := row.Scan(&m.ProjectID, &m.TenantID, &m.WorkspaceID, &m.UserID, &role, &status, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.Role = service.Role(role)
	m.Status = service.MembershipStatus(status)
	return &m, nil
}

const membershipCols = `project_id, tenant_id, workspace_id, user_id, role, status, created_at, updated_at`

func (s *Store) GetMembership(ctx context.Context, projectID, tenantID, workspaceID, userID string) (*service.Membership, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+membershipCols+` FROM memberships
		  WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3 AND user_id=$4`, projectID, tenantID, workspaceID, userID)
	return scanMembership(row)
}

func (s *Store) ListMembers(ctx context.Context, projectID, tenantID, workspaceID string) ([]*service.Membership, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+membershipCols+` FROM memberships
		  WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3
		  ORDER BY created_at, user_id`, projectID, tenantID, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Membership
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMembership(ctx context.Context, projectID, tenantID, workspaceID, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM memberships WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3 AND user_id=$4`,
		projectID, tenantID, workspaceID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

// ── invitations ─────────────────────────────────────────────────────────────

func (s *Store) CreateInvitation(ctx context.Context, inv *service.Invitation) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO invitations
		   (project_id, tenant_id, id, workspace_id, email, role, status, invited_by, token_hash, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		inv.ProjectID, inv.TenantID, inv.ID, inv.WorkspaceID, inv.Email, string(inv.Role), string(inv.Status),
		inv.InvitedBy, inv.TokenHash, inv.CreatedAt, inv.ExpiresAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanInvitation(row pgx.Row) (*service.Invitation, error) {
	var inv service.Invitation
	var role, status string
	err := row.Scan(&inv.ProjectID, &inv.TenantID, &inv.ID, &inv.WorkspaceID, &inv.Email, &role, &status,
		&inv.InvitedBy, &inv.TokenHash, &inv.CreatedAt, &inv.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	inv.Role = service.Role(role)
	inv.Status = service.InvitationStatus(status)
	return &inv, nil
}

const invitationCols = `project_id, tenant_id, id, workspace_id, email, role, status, invited_by, token_hash, created_at, expires_at`

func (s *Store) GetInvitation(ctx context.Context, projectID, tenantID, id string) (*service.Invitation, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+invitationCols+` FROM invitations WHERE project_id=$1 AND tenant_id=$2 AND id=$3`, projectID, tenantID, id)
	return scanInvitation(row)
}

func (s *Store) GetInvitationByTokenHash(ctx context.Context, projectID, tenantID, tokenHash string) (*service.Invitation, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+invitationCols+` FROM invitations WHERE project_id=$1 AND tenant_id=$2 AND token_hash=$3`, projectID, tenantID, tokenHash)
	return scanInvitation(row)
}

func (s *Store) UpdateInvitation(ctx context.Context, inv *service.Invitation) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE invitations SET workspace_id=$4, email=$5, role=$6, status=$7,
		        invited_by=$8, token_hash=$9, created_at=$10, expires_at=$11
		  WHERE project_id=$1 AND tenant_id=$2 AND id=$3`,
		inv.ProjectID, inv.TenantID, inv.ID, inv.WorkspaceID, inv.Email, string(inv.Role), string(inv.Status),
		inv.InvitedBy, inv.TokenHash, inv.CreatedAt, inv.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (s *Store) ListInvitations(ctx context.Context, projectID, tenantID, workspaceID string) ([]*service.Invitation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+invitationCols+` FROM invitations
		  WHERE project_id=$1 AND tenant_id=$2 AND workspace_id=$3
		  ORDER BY created_at, id`, projectID, tenantID, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Invitation
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// ── groups ──────────────────────────────────────────────────────────────────

func (s *Store) CreateGroup(ctx context.Context, g *service.Group) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO groups
		   (project_id, tenant_id, id, workspace_id, slug, display_name, created_by, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.ProjectID, g.TenantID, g.ID, g.WorkspaceID, g.Slug, g.DisplayName, g.CreatedBy, g.CreatedAt, g.UpdatedAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanGroup(row pgx.Row) (*service.Group, error) {
	var g service.Group
	err := row.Scan(&g.ProjectID, &g.TenantID, &g.ID, &g.WorkspaceID, &g.Slug, &g.DisplayName, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

const groupCols = `project_id, tenant_id, id, workspace_id, slug, display_name, created_by, created_at, updated_at`

func (s *Store) GetGroup(ctx context.Context, projectID, tenantID, id string) (*service.Group, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+groupCols+` FROM groups WHERE project_id=$1 AND tenant_id=$2 AND id=$3`, projectID, tenantID, id)
	return scanGroup(row)
}

func (s *Store) ListGroups(ctx context.Context, projectID, tenantID, workspaceID string) ([]*service.Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+groupCols+` FROM groups
		  WHERE project_id=$1 AND tenant_id=$2 AND ($3='' OR workspace_id=$3)
		  ORDER BY created_at, id`, projectID, tenantID, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) DeleteGroup(ctx context.Context, projectID, tenantID, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `DELETE FROM groups WHERE project_id=$1 AND tenant_id=$2 AND id=$3`, projectID, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM relation_tuples WHERE project_id=$1 AND tenant_id=$2 AND namespace='group' AND object_id=$3`,
		projectID, tenantID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
