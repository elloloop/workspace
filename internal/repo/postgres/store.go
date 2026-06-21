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
	"strings"
	"time"

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

CREATE TABLE IF NOT EXISTS enrollments (
	project_id   text        NOT NULL,
	tenant_id    text        NOT NULL DEFAULT '',
	group_id     text        NOT NULL,
	member_kind  text        NOT NULL,
	member_id    text        NOT NULL,
	state        text        NOT NULL,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, group_id, member_kind, member_id)
);

CREATE TABLE IF NOT EXISTS seat_limits (
	project_id text    NOT NULL,
	tenant_id  text    NOT NULL DEFAULT '',
	sku        text    NOT NULL,
	seat_limit integer NOT NULL,
	PRIMARY KEY (project_id, tenant_id, sku)
);

CREATE TABLE IF NOT EXISTS seat_assignments (
	project_id  text        NOT NULL,
	tenant_id   text        NOT NULL DEFAULT '',
	sku         text        NOT NULL,
	user_id     text        NOT NULL,
	assigned_at timestamptz NOT NULL,
	PRIMARY KEY (project_id, tenant_id, sku, user_id)
);

CREATE TABLE IF NOT EXISTS consistency_seq (
	project_id text   NOT NULL,
	tenant_id  text   NOT NULL DEFAULT '',
	seq        bigint NOT NULL DEFAULT 0,
	PRIMARY KEY (project_id, tenant_id)
);

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
	expires_at        timestamptz,
	condition_name    text NOT NULL DEFAULT '',
	condition_params  jsonb NOT NULL DEFAULT '{}'::jsonb,
	PRIMARY KEY (project_id, tenant_id, namespace, object_id, relation, subject_kind,
		subject_user_id, subject_namespace, subject_object_id, subject_relation)
);
ALTER TABLE relation_tuples ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT '';
ALTER TABLE relation_tuples ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE relation_tuples ADD COLUMN IF NOT EXISTS condition_name text NOT NULL DEFAULT '';
ALTER TABLE relation_tuples ADD COLUMN IF NOT EXISTS condition_params jsonb NOT NULL DEFAULT '{}'::jsonb;
`

// secondaryIndex describes a tenant-scoped partial index built during the expand
// phase. Unlike the PK widenings these never become primary keys (a PRIMARY KEY
// cannot be partial), but they are still built CONCURRENTLY so the expand never
// takes an ACCESS EXCLUSIVE lock on a populated hot-path table. dropStale, when
// true, drops a same-named index whose definition predates tenant_id (the old
// (project_id, owner_user_id) personal-workspace index) so the tenant-scoped one
// below actually replaces it.
type secondaryIndex struct {
	name      string
	table     string
	createSQL string
	dropStale bool
}

var secondaryIndexes = []secondaryIndex{
	{
		name: "workspaces_personal_uniq", table: "workspaces", dropStale: true,
		createSQL: "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS workspaces_personal_uniq " +
			"ON workspaces (project_id, tenant_id, owner_user_id) WHERE type = 'personal'",
	},
	{
		// Supports DeleteAllSubjectTuples and subject-only ReadTuples without a
		// full (project, tenant) partition scan.
		name: "relation_tuples_subject_user_idx", table: "relation_tuples",
		createSQL: "CREATE INDEX CONCURRENTLY IF NOT EXISTS relation_tuples_subject_user_idx " +
			"ON relation_tuples (project_id, tenant_id, subject_user_id) WHERE subject_kind = 'user'",
	},
}

const (
	// migrateAdvisoryLockKey serializes Migrate across replicas: only one
	// process runs the (idempotent) DDL at a time, so concurrent boots cannot
	// race the expand/contract steps. Any fixed app-unique key works.
	migrateAdvisoryLockKey int64 = 0x6D696772 // "migr"
	// migrateLockTimeout bounds how long a single migration statement waits for
	// its table lock before failing fast, so a contended hot-path table is not
	// stalled indefinitely by an auto-migration on boot. Applied per-session
	// (SET, not SET LOCAL) because the migration runs outside a single tx so
	// CREATE INDEX CONCURRENTLY is usable.
	migrateLockTimeout = "5s"
)

// pkWidening describes one table whose primary key is being widened to lead with
// (project_id, tenant_id). The expand phase builds idxName as a composite UNIQUE
// INDEX CONCURRENTLY (no ACCESS EXCLUSIVE lock, leaving the old PK intact); the
// contract phase promotes that index to the table's PRIMARY KEY and drops the
// old one. cols is the full composite key, in order.
type pkWidening struct {
	table   string
	idxName string
	cols    string
}

// pkWidenings are the five (project_id, tenant_id, …) keys widened from their
// pre-tenant single-column-leading form. Order is irrelevant (each is
// independent); idxName is the deterministic name both expand and contract use.
var pkWidenings = []pkWidening{
	{"workspaces", "workspaces_pk_tenant", "project_id, tenant_id, id"},
	{"memberships", "memberships_pk_tenant", "project_id, tenant_id, workspace_id, user_id"},
	{"invitations", "invitations_pk_tenant", "project_id, tenant_id, id"},
	{"groups", "groups_pk_tenant", "project_id, tenant_id, id"},
	{
		"relation_tuples", "relation_tuples_pk_tenant",
		"project_id, tenant_id, namespace, object_id, relation, subject_kind, " +
			"subject_user_id, subject_namespace, subject_object_id, subject_relation",
	},
}

// Migrate runs the EXPAND phase: it creates/upgrades the schema so the service
// can run, without ever taking a long ACCESS EXCLUSIVE lock on a populated
// hot-path table. It is idempotent and safe on every boot.
//
// A SESSION advisory lock (on a dedicated connection) serializes concurrent
// replicas while statements run OUTSIDE a wrapping transaction — required so
// CREATE UNIQUE INDEX CONCURRENTLY (which cannot run in a tx) is usable. A
// per-session lock_timeout makes a contended DDL fail fast instead of stalling
// the data plane.
//
// For a FRESH database, CREATE TABLE installs the composite (project_id,
// tenant_id, …) primary key directly (instant on an empty table) and the expand
// step is a no-op. For an EXISTING database still on the old single-column PK,
// the expand step builds the composite key as a UNIQUE INDEX CONCURRENTLY and
// LEAVES the old PK intact — so old and new binaries interoperate during a
// rolling deploy (ON CONFLICT targets the composite columns, satisfied by the
// new unique index). Promoting that index to the PRIMARY KEY and dropping the
// old one is the CONTRACT phase (Contract), run deliberately out of band after
// the whole fleet is on the new binary.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	unlock, err := lockAndPrepare(ctx, conn.Conn())
	if err != nil {
		return err
	}
	defer unlock()

	// Base schema: CREATE TABLE IF NOT EXISTS (+ column adds, regular indexes).
	// Cheap and idempotent; on a fresh DB this installs the composite PKs.
	if _, err := conn.Exec(ctx, schemaSQL); err != nil {
		return err
	}

	// Expand: for any table still on the old narrow PK, build the composite key
	// as a UNIQUE INDEX CONCURRENTLY (no ACCESS EXCLUSIVE lock), keeping the old
	// PK valid. CONCURRENTLY cannot run inside a transaction, so this runs on the
	// session connection directly.
	for _, w := range pkWidenings {
		if err := expandWidening(ctx, conn.Conn(), w); err != nil {
			return fmt.Errorf("expand %s: %w", w.table, err)
		}
	}
	// Tenant-scoped secondary (partial) indexes, also built CONCURRENTLY.
	for _, idx := range secondaryIndexes {
		if err := expandSecondaryIndex(ctx, conn.Conn(), idx); err != nil {
			return fmt.Errorf("expand index %s: %w", idx.name, err)
		}
	}
	return nil
}

// expandSecondaryIndex builds a tenant-scoped partial index CONCURRENTLY (never
// an ACCESS EXCLUSIVE lock). When dropStale is set it first drops a same-named
// index whose definition predates tenant_id (resolving the name in the CURRENT
// schema only, so a same-named index in a sibling schema is untouched). A leftover
// INVALID index from a failed CONCURRENTLY build is dropped before the rebuild.
func expandSecondaryIndex(ctx context.Context, conn *pgx.Conn, idx secondaryIndex) error {
	if idx.dropStale {
		var hasTenant *bool
		err := conn.QueryRow(ctx,
			`SELECT bool_or(a.attname = 'tenant_id')
			   FROM pg_index i
			   JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
			  WHERE i.indexrelid = to_regclass(current_schema() || '.' || $1)`,
			idx.name).Scan(&hasTenant)
		if err != nil {
			return err
		}
		// hasTenant is non-nil only when the index exists; drop it when it predates
		// tenant_id so the tenant-scoped definition can replace it.
		if hasTenant != nil && !*hasTenant {
			if _, err := conn.Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+idx.name); err != nil {
				return err
			}
		}
	}
	exists, valid, err := indexState(ctx, conn, idx.name)
	if err != nil {
		return err
	}
	if exists && !valid {
		if _, err := conn.Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+idx.name); err != nil {
			return err
		}
	}
	_, err = conn.Exec(ctx, idx.createSQL)
	return err
}

// Contract runs the CONTRACT phase: it promotes each composite unique index
// built by Migrate (expand) into the table's PRIMARY KEY and drops the old
// narrow PK. This DOES take a brief ACCESS EXCLUSIVE lock per table (PRIMARY KEY
// USING INDEX is metadata-only — it adopts the already-built index rather than
// rebuilding it, so the lock is short, not proportional to table size), so it is
// an explicit, deliberately-invoked step (`workspace migrate --contract`), run
// only AFTER the whole fleet is on the new binary. It is idempotent: a table
// already on the composite PK is skipped.
func (s *Store) Contract(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	unlock, err := lockAndPrepare(ctx, conn.Conn())
	if err != nil {
		return err
	}
	defer unlock()

	for _, w := range pkWidenings {
		if err := contractWidening(ctx, conn.Conn(), w); err != nil {
			return fmt.Errorf("contract %s: %w", w.table, err)
		}
	}
	return nil
}

// lockAndPrepare takes the session-level migration advisory lock on conn (so
// concurrent replicas serialize even though statements run outside a tx) and
// sets a session lock_timeout so a contended DDL fails fast. The returned
// function releases the advisory lock; it must be deferred.
func lockAndPrepare(ctx context.Context, conn *pgx.Conn) (func(), error) {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateAdvisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	unlock := func() {
		// Best-effort release on the same connection; a dropped connection also
		// releases a session lock, so a failure here cannot leak the lock.
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrateAdvisoryLockKey)
	}
	if _, err := conn.Exec(ctx, "SET lock_timeout = '"+migrateLockTimeout+"'"); err != nil {
		unlock()
		return nil, fmt.Errorf("set lock_timeout: %w", err)
	}
	return unlock, nil
}

// pkIsComposite reports whether table's PRIMARY KEY already includes tenant_id —
// i.e. the widening is already in effect (fresh DB, or a completed contract).
func pkIsComposite(ctx context.Context, conn *pgx.Conn, table string) (bool, error) {
	var composite bool
	err := conn.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_index i
			  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
			 WHERE i.indrelid = to_regclass(current_schema() || '.' || $1)
			   AND i.indisprimary AND a.attname = 'tenant_id')`,
		table).Scan(&composite)
	return composite, err
}

// indexState returns whether the named composite index exists in the current
// schema and, if so, whether it is valid (CREATE INDEX CONCURRENTLY can leave an
// INVALID index behind on failure).
func indexState(ctx context.Context, conn *pgx.Conn, idxName string) (exists, valid bool, err error) {
	err = conn.QueryRow(ctx,
		`SELECT i.indisvalid
		   FROM pg_index i
		  WHERE i.indexrelid = to_regclass(current_schema() || '.' || $1)`,
		idxName).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, valid, nil
}

// expandWidening builds w's composite key as a UNIQUE INDEX CONCURRENTLY when
// the table is still on the old narrow PK, leaving the old PK valid. It is a
// no-op when the PK is already composite (fresh DB / completed contract). A stale
// INVALID index from a previously-failed CONCURRENTLY build is dropped first so
// the rebuild can succeed (IF NOT EXISTS would otherwise skip it forever).
func expandWidening(ctx context.Context, conn *pgx.Conn, w pkWidening) error {
	composite, err := pkIsComposite(ctx, conn, w.table)
	if err != nil {
		return err
	}
	if composite {
		return nil
	}
	exists, valid, err := indexState(ctx, conn, w.idxName)
	if err != nil {
		return err
	}
	if exists && !valid {
		// DROP INDEX CONCURRENTLY also avoids an ACCESS EXCLUSIVE lock.
		if _, err := conn.Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+w.idxName); err != nil {
			return err
		}
	}
	_, err = conn.Exec(ctx,
		"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "+w.idxName+" ON "+w.table+" ("+w.cols+")")
	return err
}

// contractWidening promotes w's composite unique index to the table's PRIMARY
// KEY and drops the old narrow PK, in one short transaction. It is a no-op when
// the PK is already composite. ALTER TABLE … ADD PRIMARY KEY USING INDEX adopts
// the existing (already-built) index instead of rebuilding it, so the ACCESS
// EXCLUSIVE lock it takes is brief and independent of table size.
func contractWidening(ctx context.Context, conn *pgx.Conn, w pkWidening) error {
	composite, err := pkIsComposite(ctx, conn, w.table)
	if err != nil {
		return err
	}
	if composite {
		return nil
	}
	exists, valid, err := indexState(ctx, conn, w.idxName)
	if err != nil {
		return err
	}
	if !exists || !valid {
		return fmt.Errorf("composite index %s missing or invalid; run expand (Migrate) first", w.idxName)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "ALTER TABLE "+w.table+" DROP CONSTRAINT IF EXISTS "+w.table+"_pkey"); err != nil {
		return err
	}
	// USING INDEX consumes the unique index, turning it into the PK's backing
	// index (it is renamed to <table>_pkey by Postgres).
	if _, err := tx.Exec(ctx,
		"ALTER TABLE "+w.table+" ADD CONSTRAINT "+w.table+"_pkey PRIMARY KEY USING INDEX "+w.idxName); err != nil {
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
	Model      json.RawMessage `json:"model,omitempty"`
	DataRegion string          `json:"data_region,omitempty"`
}

func encodeProjectConfig(m authz.Model, dataRegion string) (string, error) {
	cfg := projectConfig{DataRegion: dataRegion}
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

func decodeProjectConfig(blob string) (model authz.Model, dataRegion string, err error) {
	if blob == "" {
		return nil, "", nil
	}
	var cfg projectConfig
	if err := json.Unmarshal([]byte(blob), &cfg); err != nil {
		return nil, "", err
	}
	if len(cfg.Model) == 0 {
		return nil, cfg.DataRegion, nil
	}
	m, err := authz.ParseModel(cfg.Model)
	return m, cfg.DataRegion, err
}

func (s *Store) CreateProject(ctx context.Context, p *service.Project) error {
	cfg, err := encodeProjectConfig(p.Model, p.DataRegion)
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
	model, dataRegion, err := decodeProjectConfig(cfg)
	if err != nil {
		return nil, err
	}
	p.Model = model
	p.DataRegion = dataRegion
	return &p, nil
}

const projectCols = `id, name, status, config_json, created_at, updated_at`

func (s *Store) GetProject(ctx context.Context, id string) (*service.Project, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+projectCols+` FROM projects WHERE id=$1`, id)
	return scanProject(row)
}

func (s *Store) UpdateProject(ctx context.Context, p *service.Project) error {
	cfg, err := encodeProjectConfig(p.Model, p.DataRegion)
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

// pgExec is the subset of *pgxpool.Pool / pgx.Tx the write helpers need, so the
// same SQL backs both the standalone methods and the atomic combined ones.
type pgExec interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (s *Store) WriteTuples(ctx context.Context, projectID, tenantID string, inserts, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := writeTuplesExec(ctx, tx, projectID, tenantID, inserts, deletes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// bumpSeqExec advances the shard's monotonic consistency sequence via q (a tx),
// so the bump commits atomically with the tuple write in the same transaction
// and a token issued for that write is always observed by a later read.
func bumpSeqExec(ctx context.Context, q pgExec, projectID, tenantID string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO consistency_seq (project_id, tenant_id, seq) VALUES ($1,$2,1)
		 ON CONFLICT (project_id, tenant_id) DO UPDATE SET seq = consistency_seq.seq + 1`,
		projectID, tenantID)
	return err
}

// ConsistencyToken returns the shard's current monotonic write sequence (0 if
// the shard has never been written).
func (s *Store) ConsistencyToken(ctx context.Context, projectID, tenantID string) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT seq FROM consistency_seq WHERE project_id=$1 AND tenant_id=$2), 0)`,
		projectID, tenantID).Scan(&seq)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// writeTuplesExec applies tuple deletes then inserts via q (a pool or a tx).
func writeTuplesExec(ctx context.Context, q pgExec, projectID, tenantID string, inserts, deletes []authz.Tuple) error {
	for _, t := range deletes {
		kind, uid, sns, soid, srel := tupleCols(t)
		_, err := q.Exec(ctx,
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
		condName, condParams := conditionCols(t)
		_, err := q.Exec(ctx,
			`INSERT INTO relation_tuples
			   (project_id, tenant_id, namespace, object_id, relation, subject_kind,
			    subject_user_id, subject_namespace, subject_object_id, subject_relation,
			    expires_at, condition_name, condition_params)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			 ON CONFLICT (project_id, tenant_id, namespace, object_id, relation, subject_kind,
			    subject_user_id, subject_namespace, subject_object_id, subject_relation)
			 DO UPDATE SET expires_at = EXCLUDED.expires_at,
			               condition_name = EXCLUDED.condition_name,
			               condition_params = EXCLUDED.condition_params`,
			projectID, tenantID, t.Namespace, t.ObjectID, t.Relation, kind, uid, sns, soid, srel,
			t.ExpiresAt, condName, condParams)
		if err != nil {
			return err
		}
	}
	// Advance the shard's consistency sequence for ANY tuple mutation — so a
	// membership/seat/enrollment write (which all route through here) is visible
	// to the read-after-write contract, not just the standalone WriteTuples.
	return bumpSeqExec(ctx, q, projectID, tenantID)
}

// conditionCols renders a tuple's optional condition into the stored columns:
// an empty name with an empty JSON object means "unconditional".
func conditionCols(t authz.Tuple) (name string, params []byte) {
	c := t.Subject.Condition
	if c == nil || c.Name == "" {
		return "", []byte("{}")
	}
	p := c.Params
	if p == nil {
		p = map[string]any{}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return c.Name, []byte("{}")
	}
	return c.Name, b
}

func scanTuple(row pgx.Row) (authz.Tuple, error) {
	var t authz.Tuple
	var kind, uid, sns, soid, srel, condName string
	var condParams []byte
	var expires *time.Time
	if err := row.Scan(&t.Namespace, &t.ObjectID, &t.Relation, &kind, &uid, &sns, &soid, &srel, &expires, &condName, &condParams); err != nil {
		return t, err
	}
	t.ExpiresAt = expires
	switch kind {
	case "set":
		t.Subject.Set = &authz.SubjectSet{Namespace: sns, ObjectID: soid, Relation: srel}
	case "wildcard":
		t.Subject.Wildcard = true
	default:
		t.Subject.UserID = uid
	}
	if condName != "" {
		var params map[string]any
		if len(condParams) > 0 {
			if err := json.Unmarshal(condParams, &params); err != nil {
				return t, err
			}
		}
		t.Subject.Condition = &authz.Condition{Name: condName, Params: params}
	}
	return t, nil
}

func (s *Store) ListSubjects(ctx context.Context, projectID, tenantID, namespace, objectID, relation string) ([]authz.Subject, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT namespace, object_id, relation, subject_kind, subject_user_id,
		        subject_namespace, subject_object_id, subject_relation, expires_at, condition_name, condition_params
		   FROM relation_tuples
		  WHERE project_id=$1 AND tenant_id=$2 AND namespace=$3 AND object_id=$4 AND relation=$5
		    AND (expires_at IS NULL OR expires_at > now())`,
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
		    AND (expires_at IS NULL OR expires_at > now())
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
		        subject_namespace, subject_object_id, subject_relation, expires_at, condition_name, condition_params
		   FROM relation_tuples
		  WHERE project_id=$1 AND tenant_id=$2
		    AND ($3='' OR namespace=$3)
		    AND ($4='' OR object_id=$4)
		    AND ($5='' OR relation=$5)
		    AND ($6='' OR subject_user_id=$6)
		    AND (expires_at IS NULL OR expires_at > now())
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
	// Project-wide erase across ALL tenants, in one transaction: the user's
	// relation tuples AND their seat assignments (so deprovisioning reclaims paid
	// seats and leaves no entitlement residue). project_id leads both the
	// relation_tuples_subject_user_idx index and the seat_assignments PK, so
	// dropping the tenant_id filter still uses them.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`DELETE FROM relation_tuples
		  WHERE project_id=$1 AND subject_kind='user' AND subject_user_id=$2`,
		projectID, userID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM seat_assignments WHERE project_id=$1 AND user_id=$2`,
		projectID, userID); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

const tupleAtCols = `tenant_id, namespace, object_id, relation, subject_kind, subject_user_id,
	subject_namespace, subject_object_id, subject_relation, expires_at, condition_name, condition_params`

func scanTupleAt(row pgx.Row) (service.TupleAt, error) {
	var ta service.TupleAt
	var t authz.Tuple
	var kind, uid, sns, soid, srel, condName string
	var condParams []byte
	var expires *time.Time
	if err := row.Scan(&ta.TenantID, &t.Namespace, &t.ObjectID, &t.Relation, &kind, &uid, &sns, &soid, &srel, &expires, &condName, &condParams); err != nil {
		return ta, err
	}
	t.ExpiresAt = expires
	switch kind {
	case "set":
		t.Subject.Set = &authz.SubjectSet{Namespace: sns, ObjectID: soid, Relation: srel}
	case "wildcard":
		t.Subject.Wildcard = true
	default:
		t.Subject.UserID = uid
	}
	if condName != "" {
		var params map[string]any
		if len(condParams) > 0 {
			if err := json.Unmarshal(condParams, &params); err != nil {
				return ta, err
			}
		}
		t.Subject.Condition = &authz.Condition{Name: condName, Params: params}
	}
	ta.Tuple = t
	return ta, nil
}

func (s *Store) ListSubjectTuplesInProject(ctx context.Context, projectID, userID string) ([]service.TupleAt, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+tupleAtCols+`
		   FROM relation_tuples
		  WHERE project_id=$1 AND subject_kind='user' AND subject_user_id=$2
		    AND (expires_at IS NULL OR expires_at > now())
		  ORDER BY tenant_id, namespace, object_id, relation`,
		projectID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectTupleAt(rows)
}

func (s *Store) ListTuplesForSubjectSetsInProject(ctx context.Context, projectID string, sets []authz.SubjectSet) ([]service.TupleAt, error) {
	if len(sets) == 0 {
		return nil, nil
	}
	args := []any{projectID}
	var vals strings.Builder
	for i, st := range sets {
		if i > 0 {
			vals.WriteByte(',')
		}
		base := len(args)
		fmt.Fprintf(&vals, "($%d,$%d,$%d)", base+1, base+2, base+3)
		args = append(args, st.Namespace, st.ObjectID, st.Relation)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+tupleAtCols+`
		   FROM relation_tuples
		  WHERE project_id=$1 AND subject_kind='set'
		    AND (subject_namespace, subject_object_id, subject_relation) IN (`+vals.String()+`)
		    AND (expires_at IS NULL OR expires_at > now())
		  ORDER BY tenant_id, namespace, object_id, relation`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectTupleAt(rows)
}

func collectTupleAt(rows pgx.Rows) ([]service.TupleAt, error) {
	var out []service.TupleAt
	for rows.Next() {
		ta, err := scanTupleAt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ta)
	}
	return out, rows.Err()
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
	if err := bumpSeqExec(ctx, tx, projectID, tenantID); err != nil {
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
	return putMembershipExec(ctx, s.pool, m)
}

// putMembershipExec upserts the membership row via q (a pool or a tx).
func putMembershipExec(ctx context.Context, q pgExec, m *service.Membership) error {
	_, err := q.Exec(ctx,
		`INSERT INTO memberships
		   (project_id, tenant_id, workspace_id, user_id, role, status, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (project_id, tenant_id, workspace_id, user_id) DO UPDATE
		   SET role=EXCLUDED.role, status=EXCLUDED.status,
		       created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at`,
		m.ProjectID, m.TenantID, m.WorkspaceID, m.UserID, string(m.Role), string(m.Status), m.CreatedAt, m.UpdatedAt)
	return err
}

// PutMembershipAndTuples upserts the membership and applies the tuple writes in
// one transaction.
func (s *Store) PutMembershipAndTuples(ctx context.Context, m *service.Membership, inserts, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := putMembershipExec(ctx, tx, m); err != nil {
		return err
	}
	if err := writeTuplesExec(ctx, tx, m.ProjectID, m.TenantID, inserts, deletes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteMembershipAndTuples deletes the membership row and the given tuples in
// one transaction; ErrNotFound rolls back, leaving both untouched.
func (s *Store) DeleteMembershipAndTuples(ctx context.Context, projectID, tenantID, workspaceID, userID string, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := deleteMembershipExec(ctx, tx, projectID, tenantID, workspaceID, userID); err != nil {
		return err
	}
	if err := writeTuplesExec(ctx, tx, projectID, tenantID, nil, deletes); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	return deleteMembershipExec(ctx, s.pool, projectID, tenantID, workspaceID, userID)
}

// deleteMembershipExec deletes the membership row via q; ErrNotFound if absent.
func deleteMembershipExec(ctx context.Context, q pgExec, projectID, tenantID, workspaceID, userID string) error {
	tag, err := q.Exec(ctx,
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
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollments WHERE project_id=$1 AND tenant_id=$2 AND group_id=$3`,
		projectID, tenantID, id); err != nil {
		return err
	}
	if err := bumpSeqExec(ctx, tx, projectID, tenantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ── enrollments ─────────────────────────────────────────────────────────────

// SetEnrollmentAndTuples upserts the enrollment row and applies the tuple writes
// in one transaction.
func (s *Store) SetEnrollmentAndTuples(ctx context.Context, e *service.Enrollment, inserts, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	kind, id := service.MemberKey(e.Member)
	if _, err := tx.Exec(ctx,
		`INSERT INTO enrollments
		   (project_id, tenant_id, group_id, member_kind, member_id, state, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (project_id, tenant_id, group_id, member_kind, member_id) DO UPDATE
		   SET state=EXCLUDED.state, created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at`,
		e.ProjectID, e.TenantID, e.GroupID, kind, id, string(e.State), e.CreatedAt, e.UpdatedAt); err != nil {
		return err
	}
	if err := writeTuplesExec(ctx, tx, e.ProjectID, e.TenantID, inserts, deletes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scanEnrollment(row pgx.Row) (*service.Enrollment, error) {
	var e service.Enrollment
	var kind, id, state string
	err := row.Scan(&e.ProjectID, &e.TenantID, &e.GroupID, &kind, &id, &state, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.Member = service.MemberFromKey(kind, id)
	e.State = service.EnrollmentState(state)
	return &e, nil
}

const enrollmentCols = `project_id, tenant_id, group_id, member_kind, member_id, state, created_at, updated_at`

func (s *Store) GetEnrollment(ctx context.Context, projectID, tenantID, groupID string, member service.GroupMember) (*service.Enrollment, error) {
	kind, id := service.MemberKey(member)
	row := s.pool.QueryRow(ctx,
		`SELECT `+enrollmentCols+` FROM enrollments
		  WHERE project_id=$1 AND tenant_id=$2 AND group_id=$3 AND member_kind=$4 AND member_id=$5`,
		projectID, tenantID, groupID, kind, id)
	return scanEnrollment(row)
}

func (s *Store) ListEnrollments(ctx context.Context, projectID, tenantID, groupID string) ([]*service.Enrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+enrollmentCols+` FROM enrollments
		  WHERE project_id=$1 AND tenant_id=$2 AND group_id=$3
		  ORDER BY created_at, member_kind, member_id`, projectID, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── seats (license/entitlement counting) ────────────────────────────────────

func (s *Store) SetSeatLimit(ctx context.Context, projectID, tenantID, sku string, limit *int) error {
	if limit == nil {
		// Clear the cap → unlimited.
		_, err := s.pool.Exec(ctx,
			`DELETE FROM seat_limits WHERE project_id=$1 AND tenant_id=$2 AND sku=$3`,
			projectID, tenantID, sku)
		return err
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO seat_limits (project_id, tenant_id, sku, seat_limit)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (project_id, tenant_id, sku) DO UPDATE SET seat_limit=EXCLUDED.seat_limit`,
		projectID, tenantID, sku, *limit)
	return err
}

func (s *Store) GetSeatUsage(ctx context.Context, projectID, tenantID, sku string) (service.SeatUsage, error) {
	u := service.SeatUsage{SKU: sku}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM seat_assignments WHERE project_id=$1 AND tenant_id=$2 AND sku=$3`,
		projectID, tenantID, sku).Scan(&u.Used); err != nil {
		return service.SeatUsage{}, err
	}
	var limit int
	err := s.pool.QueryRow(ctx,
		`SELECT seat_limit FROM seat_limits WHERE project_id=$1 AND tenant_id=$2 AND sku=$3`,
		projectID, tenantID, sku).Scan(&limit)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No limit configured → unlimited.
	case err != nil:
		return service.SeatUsage{}, err
	default:
		u.Limit, u.Limited = limit, true
	}
	return u, nil
}

// seatLockKey serializes concurrent AssignSeat for one (project, tenant, sku) so
// the count-check and insert cannot interleave and oversubscribe the cap.
func seatLockKey(projectID, tenantID, sku string) string {
	// Joined with the unit separator (0x1F): valid in Postgres text (unlike NUL)
	// and not a character ids contain, so distinct skus map to distinct keys.
	return "seat\x1f" + projectID + "\x1f" + tenantID + "\x1f" + sku
}

func (s *Store) AssignSeatAndTuple(ctx context.Context, a *service.SeatAssignment, tuple authz.Tuple) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize assigns for this sku; the lock is released on commit/rollback.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
		seatLockKey(a.ProjectID, a.TenantID, a.SKU)); err != nil {
		return false, err
	}

	// Idempotent: a user who already holds a seat consumes no extra one.
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM seat_assignments
		   WHERE project_id=$1 AND tenant_id=$2 AND sku=$3 AND user_id=$4)`,
		a.ProjectID, a.TenantID, a.SKU, a.UserID).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		// Self-heal: re-assert the backing tuple (idempotent upsert) so a counted
		// seat whose tuple was deleted out-of-band converges back to granting.
		if err := writeTuplesExec(ctx, tx, a.ProjectID, a.TenantID, []authz.Tuple{tuple}, nil); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	// Enforce the cap (no limit row = unlimited).
	var limit int
	switch err := tx.QueryRow(ctx,
		`SELECT seat_limit FROM seat_limits WHERE project_id=$1 AND tenant_id=$2 AND sku=$3`,
		a.ProjectID, a.TenantID, a.SKU).Scan(&limit); {
	case errors.Is(err, pgx.ErrNoRows):
		// unlimited
	case err != nil:
		return false, err
	default:
		var used int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM seat_assignments WHERE project_id=$1 AND tenant_id=$2 AND sku=$3`,
			a.ProjectID, a.TenantID, a.SKU).Scan(&used); err != nil {
			return false, err
		}
		if used >= limit {
			return false, service.ErrResourceExhausted
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO seat_assignments (project_id, tenant_id, sku, user_id, assigned_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		a.ProjectID, a.TenantID, a.SKU, a.UserID, a.AssignedAt); err != nil {
		return false, err
	}
	if err := writeTuplesExec(ctx, tx, a.ProjectID, a.TenantID, []authz.Tuple{tuple}, nil); err != nil {
		return false, err
	}
	return false, tx.Commit(ctx)
}

func (s *Store) RevokeSeatAndTuple(ctx context.Context, projectID, tenantID, sku, userID string, tuple authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`DELETE FROM seat_assignments WHERE project_id=$1 AND tenant_id=$2 AND sku=$3 AND user_id=$4`,
		projectID, tenantID, sku, userID); err != nil {
		return err
	}
	if err := writeTuplesExec(ctx, tx, projectID, tenantID, nil, []authz.Tuple{tuple}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListSeats(ctx context.Context, projectID, tenantID, sku string) ([]*service.SeatAssignment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT project_id, tenant_id, sku, user_id, assigned_at FROM seat_assignments
		  WHERE project_id=$1 AND tenant_id=$2 AND sku=$3
		  ORDER BY assigned_at, user_id`, projectID, tenantID, sku)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*service.SeatAssignment
	for rows.Next() {
		var a service.SeatAssignment
		if err := rows.Scan(&a.ProjectID, &a.TenantID, &a.SKU, &a.UserID, &a.AssignedAt); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
