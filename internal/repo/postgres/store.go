// Package postgres is the Postgres Repository driver. It satisfies
// service.Repository (and thus authz.TupleReader) over a pgxpool, matching
// the in-memory reference driver's semantics exactly. Every table is sharded
// by project_id (identity ADR-0002): project_id is the leading column of every
// primary key and index, and every WHERE clause filters on it.
package postgres

import (
	"context"
	"errors"

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
CREATE TABLE IF NOT EXISTS workspaces (
	project_id     text        NOT NULL,
	id             text        NOT NULL,
	slug           text        NOT NULL,
	display_name   text        NOT NULL,
	type           text        NOT NULL,
	owner_user_id  text        NOT NULL,
	created_at     timestamptz NOT NULL,
	updated_at     timestamptz NOT NULL,
	PRIMARY KEY (project_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS workspaces_personal_uniq
	ON workspaces (project_id, owner_user_id)
	WHERE type = 'personal';

CREATE TABLE IF NOT EXISTS memberships (
	project_id   text        NOT NULL,
	workspace_id text        NOT NULL,
	user_id      text        NOT NULL,
	role         text        NOT NULL,
	status       text        NOT NULL,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, workspace_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitations (
	project_id   text        NOT NULL,
	id           text        NOT NULL,
	workspace_id text        NOT NULL,
	email        text        NOT NULL,
	role         text        NOT NULL,
	status       text        NOT NULL,
	invited_by   text        NOT NULL,
	token_hash   text        NOT NULL,
	created_at   timestamptz NOT NULL,
	expires_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, id)
);
CREATE INDEX IF NOT EXISTS invitations_token_idx
	ON invitations (project_id, token_hash);
CREATE INDEX IF NOT EXISTS invitations_workspace_idx
	ON invitations (project_id, workspace_id);

CREATE TABLE IF NOT EXISTS groups (
	project_id   text        NOT NULL,
	id           text        NOT NULL,
	workspace_id text        NOT NULL,
	slug         text        NOT NULL,
	display_name text        NOT NULL,
	created_by   text        NOT NULL,
	created_at   timestamptz NOT NULL,
	updated_at   timestamptz NOT NULL,
	PRIMARY KEY (project_id, id)
);
CREATE INDEX IF NOT EXISTS groups_workspace_idx
	ON groups (project_id, workspace_id);

CREATE TABLE IF NOT EXISTS relation_tuples (
	project_id        text NOT NULL,
	namespace         text NOT NULL,
	object_id         text NOT NULL,
	relation          text NOT NULL,
	subject_kind      text NOT NULL,
	subject_user_id   text NOT NULL DEFAULT '',
	subject_namespace text NOT NULL DEFAULT '',
	subject_object_id text NOT NULL DEFAULT '',
	subject_relation  text NOT NULL DEFAULT '',
	PRIMARY KEY (project_id, namespace, object_id, relation, subject_kind,
		subject_user_id, subject_namespace, subject_object_id, subject_relation)
);
`

// Migrate creates the schema if absent. It is idempotent.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	return err
}

// isUniqueViolation reports whether err is a Postgres unique_violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ── relation tuples ─────────────────────────────────────────────────────────

func tupleCols(t authz.Tuple) (kind, userID, ns, objID, rel string) {
	if t.Subject.Set != nil {
		return "set", "", t.Subject.Set.Namespace, t.Subject.Set.ObjectID, t.Subject.Set.Relation
	}
	return "user", t.Subject.UserID, "", "", ""
}

func (s *Store) WriteTuples(ctx context.Context, projectID string, inserts, deletes []authz.Tuple) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, t := range deletes {
		kind, uid, sns, soid, srel := tupleCols(t)
		_, err := tx.Exec(ctx,
			`DELETE FROM relation_tuples WHERE project_id=$1 AND namespace=$2 AND object_id=$3
			   AND relation=$4 AND subject_kind=$5 AND subject_user_id=$6
			   AND subject_namespace=$7 AND subject_object_id=$8 AND subject_relation=$9`,
			projectID, t.Namespace, t.ObjectID, t.Relation, kind, uid, sns, soid, srel)
		if err != nil {
			return err
		}
	}
	for _, t := range inserts {
		kind, uid, sns, soid, srel := tupleCols(t)
		_, err := tx.Exec(ctx,
			`INSERT INTO relation_tuples
			   (project_id, namespace, object_id, relation, subject_kind,
			    subject_user_id, subject_namespace, subject_object_id, subject_relation)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			projectID, t.Namespace, t.ObjectID, t.Relation, kind, uid, sns, soid, srel)
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
	if kind == "set" {
		t.Subject.Set = &authz.SubjectSet{Namespace: sns, ObjectID: soid, Relation: srel}
	} else {
		t.Subject.UserID = uid
	}
	return t, nil
}

func (s *Store) ListSubjects(ctx context.Context, projectID, namespace, objectID, relation string) ([]authz.Subject, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT namespace, object_id, relation, subject_kind, subject_user_id,
		        subject_namespace, subject_object_id, subject_relation
		   FROM relation_tuples
		  WHERE project_id=$1 AND namespace=$2 AND object_id=$3 AND relation=$4`,
		projectID, namespace, objectID, relation)
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

func (s *Store) ReadTuples(ctx context.Context, projectID string, f service.TupleFilter) ([]authz.Tuple, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT namespace, object_id, relation, subject_kind, subject_user_id,
		        subject_namespace, subject_object_id, subject_relation
		   FROM relation_tuples
		  WHERE project_id=$1
		    AND ($2='' OR namespace=$2)
		    AND ($3='' OR object_id=$3)
		    AND ($4='' OR relation=$4)
		    AND ($5='' OR subject_user_id=$5)
		  ORDER BY namespace, object_id, relation, subject_kind, subject_user_id,
		           subject_namespace, subject_object_id, subject_relation`,
		projectID, f.Namespace, f.ObjectID, f.Relation, f.SubjectUserID)
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

// ── workspaces ──────────────────────────────────────────────────────────────

func (s *Store) CreateWorkspace(ctx context.Context, w *service.Workspace) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO workspaces
		   (project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		w.ProjectID, w.ID, w.Slug, w.DisplayName, string(w.Type), w.OwnerUserID, w.CreatedAt, w.UpdatedAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanWorkspace(row pgx.Row) (*service.Workspace, error) {
	var w service.Workspace
	var typ string
	err := row.Scan(&w.ProjectID, &w.ID, &w.Slug, &w.DisplayName, &typ, &w.OwnerUserID, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	w.Type = service.WorkspaceType(typ)
	return &w, nil
}

const workspaceCols = `project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at`

func (s *Store) GetWorkspace(ctx context.Context, projectID, id string) (*service.Workspace, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+workspaceCols+` FROM workspaces WHERE project_id=$1 AND id=$2`, projectID, id)
	return scanWorkspace(row)
}

func (s *Store) UpdateWorkspace(ctx context.Context, w *service.Workspace) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE workspaces SET slug=$3, display_name=$4, type=$5, owner_user_id=$6,
		        created_at=$7, updated_at=$8
		  WHERE project_id=$1 AND id=$2`,
		w.ProjectID, w.ID, w.Slug, w.DisplayName, string(w.Type), w.OwnerUserID, w.CreatedAt, w.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteWorkspace(ctx context.Context, projectID, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `DELETE FROM workspaces WHERE project_id=$1 AND id=$2`, projectID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE project_id=$1 AND workspace_id=$2`, projectID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM invitations WHERE project_id=$1 AND workspace_id=$2`, projectID, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM relation_tuples WHERE project_id=$1 AND namespace='workspace' AND object_id=$2`,
		projectID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PersonalWorkspace(ctx context.Context, projectID, userID string) (*service.Workspace, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+workspaceCols+` FROM workspaces
		  WHERE project_id=$1 AND owner_user_id=$2 AND type='personal'`, projectID, userID)
	return scanWorkspace(row)
}

func (s *Store) WorkspacesForUser(ctx context.Context, projectID, userID string) ([]*service.Workspace, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT w.project_id, w.id, w.slug, w.display_name, w.type, w.owner_user_id,
		        w.created_at, w.updated_at
		   FROM workspaces w
		   JOIN memberships m
		     ON m.project_id=w.project_id AND m.workspace_id=w.id
		  WHERE w.project_id=$1 AND m.user_id=$2 AND m.status='active'
		  ORDER BY w.created_at, w.id`,
		projectID, userID)
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
		   (project_id, workspace_id, user_id, role, status, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (project_id, workspace_id, user_id) DO UPDATE
		   SET role=EXCLUDED.role, status=EXCLUDED.status,
		       created_at=EXCLUDED.created_at, updated_at=EXCLUDED.updated_at`,
		m.ProjectID, m.WorkspaceID, m.UserID, string(m.Role), string(m.Status), m.CreatedAt, m.UpdatedAt)
	return err
}

func scanMembership(row pgx.Row) (*service.Membership, error) {
	var m service.Membership
	var role, status string
	err := row.Scan(&m.ProjectID, &m.WorkspaceID, &m.UserID, &role, &status, &m.CreatedAt, &m.UpdatedAt)
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

const membershipCols = `project_id, workspace_id, user_id, role, status, created_at, updated_at`

func (s *Store) GetMembership(ctx context.Context, projectID, workspaceID, userID string) (*service.Membership, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+membershipCols+` FROM memberships
		  WHERE project_id=$1 AND workspace_id=$2 AND user_id=$3`, projectID, workspaceID, userID)
	return scanMembership(row)
}

func (s *Store) ListMembers(ctx context.Context, projectID, workspaceID string) ([]*service.Membership, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+membershipCols+` FROM memberships
		  WHERE project_id=$1 AND workspace_id=$2
		  ORDER BY created_at, user_id`, projectID, workspaceID)
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

func (s *Store) DeleteMembership(ctx context.Context, projectID, workspaceID, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM memberships WHERE project_id=$1 AND workspace_id=$2 AND user_id=$3`,
		projectID, workspaceID, userID)
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
		   (project_id, id, workspace_id, email, role, status, invited_by, token_hash, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		inv.ProjectID, inv.ID, inv.WorkspaceID, inv.Email, string(inv.Role), string(inv.Status),
		inv.InvitedBy, inv.TokenHash, inv.CreatedAt, inv.ExpiresAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanInvitation(row pgx.Row) (*service.Invitation, error) {
	var inv service.Invitation
	var role, status string
	err := row.Scan(&inv.ProjectID, &inv.ID, &inv.WorkspaceID, &inv.Email, &role, &status,
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

const invitationCols = `project_id, id, workspace_id, email, role, status, invited_by, token_hash, created_at, expires_at`

func (s *Store) GetInvitation(ctx context.Context, projectID, id string) (*service.Invitation, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+invitationCols+` FROM invitations WHERE project_id=$1 AND id=$2`, projectID, id)
	return scanInvitation(row)
}

func (s *Store) GetInvitationByTokenHash(ctx context.Context, projectID, tokenHash string) (*service.Invitation, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+invitationCols+` FROM invitations WHERE project_id=$1 AND token_hash=$2`, projectID, tokenHash)
	return scanInvitation(row)
}

func (s *Store) UpdateInvitation(ctx context.Context, inv *service.Invitation) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE invitations SET workspace_id=$3, email=$4, role=$5, status=$6,
		        invited_by=$7, token_hash=$8, created_at=$9, expires_at=$10
		  WHERE project_id=$1 AND id=$2`,
		inv.ProjectID, inv.ID, inv.WorkspaceID, inv.Email, string(inv.Role), string(inv.Status),
		inv.InvitedBy, inv.TokenHash, inv.CreatedAt, inv.ExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return nil
}

func (s *Store) ListInvitations(ctx context.Context, projectID, workspaceID string) ([]*service.Invitation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+invitationCols+` FROM invitations
		  WHERE project_id=$1 AND workspace_id=$2
		  ORDER BY created_at, id`, projectID, workspaceID)
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
		   (project_id, id, workspace_id, slug, display_name, created_by, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		g.ProjectID, g.ID, g.WorkspaceID, g.Slug, g.DisplayName, g.CreatedBy, g.CreatedAt, g.UpdatedAt)
	if isUniqueViolation(err) {
		return service.ErrAlreadyExists
	}
	return err
}

func scanGroup(row pgx.Row) (*service.Group, error) {
	var g service.Group
	err := row.Scan(&g.ProjectID, &g.ID, &g.WorkspaceID, &g.Slug, &g.DisplayName, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, service.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

const groupCols = `project_id, id, workspace_id, slug, display_name, created_by, created_at, updated_at`

func (s *Store) GetGroup(ctx context.Context, projectID, id string) (*service.Group, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+groupCols+` FROM groups WHERE project_id=$1 AND id=$2`, projectID, id)
	return scanGroup(row)
}

func (s *Store) ListGroups(ctx context.Context, projectID, workspaceID string) ([]*service.Group, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+groupCols+` FROM groups
		  WHERE project_id=$1 AND ($2='' OR workspace_id=$2)
		  ORDER BY created_at, id`, projectID, workspaceID)
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

func (s *Store) DeleteGroup(ctx context.Context, projectID, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `DELETE FROM groups WHERE project_id=$1 AND id=$2`, projectID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM relation_tuples WHERE project_id=$1 AND namespace='group' AND object_id=$2`,
		projectID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
