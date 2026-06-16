package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/repo/postgres"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// oldSchemaSQL is the pre-tenant schema as it shipped on main: single-tenant
// primary keys and a (project_id, owner_user_id) personal-workspace index, with
// no tenant_id column and no projects table.
const oldSchemaSQL = `
DROP TABLE IF EXISTS projects, workspaces, memberships, invitations, groups, relation_tuples CASCADE;
CREATE TABLE workspaces (
	project_id text NOT NULL, id text NOT NULL, slug text NOT NULL, display_name text NOT NULL,
	type text NOT NULL, owner_user_id text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
	PRIMARY KEY (project_id, id));
CREATE UNIQUE INDEX workspaces_personal_uniq ON workspaces (project_id, owner_user_id) WHERE type = 'personal';
CREATE TABLE memberships (
	project_id text NOT NULL, workspace_id text NOT NULL, user_id text NOT NULL, role text NOT NULL,
	status text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
	PRIMARY KEY (project_id, workspace_id, user_id));
CREATE TABLE invitations (
	project_id text NOT NULL, id text NOT NULL, workspace_id text NOT NULL, email text NOT NULL, role text NOT NULL,
	status text NOT NULL, invited_by text NOT NULL, token_hash text NOT NULL,
	created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, PRIMARY KEY (project_id, id));
CREATE TABLE groups (
	project_id text NOT NULL, id text NOT NULL, workspace_id text NOT NULL, slug text NOT NULL,
	display_name text NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
	PRIMARY KEY (project_id, id));
CREATE TABLE relation_tuples (
	project_id text NOT NULL, namespace text NOT NULL, object_id text NOT NULL, relation text NOT NULL,
	subject_kind text NOT NULL, subject_user_id text NOT NULL DEFAULT '', subject_namespace text NOT NULL DEFAULT '',
	subject_object_id text NOT NULL DEFAULT '', subject_relation text NOT NULL DEFAULT '',
	PRIMARY KEY (project_id, namespace, object_id, relation, subject_kind,
		subject_user_id, subject_namespace, subject_object_id, subject_relation));
`

// TestMigrateUpgradesPreTenantSchema reproduces the production upgrade path the
// conformance suite (always fresh) can't: it builds the OLD single-tenant
// schema, seeds default-tenant rows, runs Migrate, and asserts the composite
// (project_id, tenant_id, …) keys are actually applied — so PutMembership's
// ON CONFLICT resolves and two tenants can hold the same logical id/tuple.
func TestMigrateUpgradesPreTenantSchema(t *testing.T) {
	dsn := os.Getenv("WORKSPACES_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set WORKSPACES_TEST_POSTGRES_DSN or GATEWAY_TEST_POSTGRES_DSN to run the migration upgrade test")
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)

	// Stand up the pre-tenant schema and seed a default-tenant row + tuple.
	if _, err := store.Pool().Exec(ctx, oldSchemaSQL); err != nil {
		t.Fatalf("old schema: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := store.Pool().Exec(ctx,
		`INSERT INTO workspaces (project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
		 VALUES ('p','w1','w1','w1','team','u1',$1,$1)`, now); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	// Migrate twice to prove idempotency (the second run must be a clean no-op).
	for i := 0; i < 2; i++ {
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i, err)
		}
	}

	// PutMembership upsert must resolve its ON CONFLICT against the widened PK.
	m := &service.Membership{
		ProjectID: "p", TenantID: "", WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleOwner, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.PutMembership(ctx, m); err != nil {
		t.Fatalf("PutMembership insert (ON CONFLICT 42P10 if PK not widened): %v", err)
	}
	m.Role = service.RoleAdmin
	if err := store.PutMembership(ctx, m); err != nil {
		t.Fatalf("PutMembership upsert: %v", err)
	}

	// The same workspace id must be reusable in a second tenant.
	ws := func(tenant string) *service.Workspace {
		return &service.Workspace{
			ID: "shared", ProjectID: "p", TenantID: tenant, Slug: "s", DisplayName: "s",
			Type: service.TypeTeam, OwnerUserID: "o", CreatedAt: now, UpdatedAt: now,
		}
	}
	if err := store.CreateWorkspace(ctx, ws("t1")); err != nil {
		t.Fatalf("workspace in t1: %v", err)
	}
	if err := store.CreateWorkspace(ctx, ws("t2")); err != nil {
		t.Fatalf("same workspace id must be reusable across tenants after migrate: %v", err)
	}

	// A personal workspace for the same owner must be allowed in two tenants.
	personal := func(tenant, id string) *service.Workspace {
		return &service.Workspace{
			ID: id, ProjectID: "p", TenantID: tenant, Slug: id, DisplayName: id,
			Type: service.TypePersonal, OwnerUserID: "owner", CreatedAt: now, UpdatedAt: now,
		}
	}
	if err := store.CreateWorkspace(ctx, personal("t1", "pw1")); err != nil {
		t.Fatalf("personal in t1: %v", err)
	}
	if err := store.CreateWorkspace(ctx, personal("t2", "pw2")); err != nil {
		t.Fatalf("personal for same owner must be allowed in another tenant: %v", err)
	}

	// The same logical tuple must persist independently in two tenants.
	tup := authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "viewer", Subject: authz.Subject{UserID: "bob"}}
	if err := store.WriteTuples(ctx, "p", "t1", []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("tuple t1: %v", err)
	}
	if err := store.WriteTuples(ctx, "p", "t2", []authz.Tuple{tup}, nil); err != nil {
		t.Fatalf("tuple t2: %v", err)
	}
	for _, tn := range []string{"t1", "t2"} {
		subs, err := store.ListSubjects(ctx, "p", tn, "doc", "d1", "viewer")
		if err != nil {
			t.Fatalf("ListSubjects %s: %v", tn, err)
		}
		if len(subs) != 1 || subs[0].UserID != "bob" {
			t.Fatalf("tenant %s lost its tuple (cross-tenant collision): %+v", tn, subs)
		}
	}
}

// TestMigrateIgnoresSameNamedIndexInOtherSchema pins the schema-qualification
// fix: a workspaces_personal_uniq index in a DIFFERENT schema of the same
// database must not trigger or abort the migration's drop-stale-index block.
func TestMigrateIgnoresSameNamedIndexInOtherSchema(t *testing.T) {
	dsn := os.Getenv("WORKSPACES_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set WORKSPACES_TEST_POSTGRES_DSN or GATEWAY_TEST_POSTGRES_DSN to run the migration schema-isolation test")
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	p := store.Pool()

	// A sibling schema holds a same-named index with the OLD (2-column) shape.
	const sibling = "ws_sibling_idxtest"
	if _, err := p.Exec(ctx, `DROP SCHEMA IF EXISTS `+sibling+` CASCADE;
		CREATE SCHEMA `+sibling+`;
		CREATE TABLE `+sibling+`.workspaces (project_id text, owner_user_id text, type text);
		CREATE UNIQUE INDEX workspaces_personal_uniq ON `+sibling+`.workspaces (project_id, owner_user_id) WHERE type='personal';`); err != nil {
		t.Fatalf("sibling schema setup: %v", err)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+sibling+` CASCADE`) })

	// Migrate in the current schema must succeed despite the sibling index.
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate aborted on a same-named index in another schema: %v", err)
	}
	// The sibling index is untouched (still the old 2-column definition).
	var cols int
	if err := p.QueryRow(ctx,
		`SELECT count(*) FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=ANY(i.indkey)
		 WHERE i.indexrelid=('`+sibling+`.workspaces_personal_uniq')::regclass`).Scan(&cols); err != nil {
		t.Fatalf("sibling index check: %v", err)
	}
	if cols != 2 {
		t.Fatalf("sibling index was modified (indexed cols=%d, want 2)", cols)
	}
}
