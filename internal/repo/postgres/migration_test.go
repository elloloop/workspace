package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/repo/postgres"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// testPostgresDSN returns the test Postgres DSN, skipping the test when neither
// env var is set. WORKSPACES_TEST_POSTGRES_DSN is the local name;
// GATEWAY_TEST_POSTGRES_DSN is the name CI's coverage job provides.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("WORKSPACES_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("GATEWAY_TEST_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set WORKSPACES_TEST_POSTGRES_DSN or GATEWAY_TEST_POSTGRES_DSN to run the Postgres tests")
	}
	return dsn
}

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
	dsn := testPostgresDSN(t)
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

	// Expand twice to prove idempotency (the second run must be a clean no-op):
	// it builds the composite unique indexes CONCURRENTLY while leaving the old
	// narrow PKs intact, so old/new binaries interoperate during a rolling deploy.
	for i := 0; i < 2; i++ {
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("Migrate (expand) run %d: %v", i, err)
		}
	}
	// Contract twice to prove idempotency: it promotes those composite indexes to
	// PRIMARY KEY and drops the old narrow PK, so cross-tenant id/tuple reuse
	// (asserted below) becomes possible. A second run is a clean no-op.
	for i := 0; i < 2; i++ {
		if err := store.Contract(ctx); err != nil {
			t.Fatalf("Contract run %d: %v", i, err)
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

// seedOldPopulated stands up the pre-tenant schema in the current isolated
// schema and seeds one default-tenant workspace + membership + tuple, so expand
// runs against populated tables. It returns the seeding timestamp.
func seedOldPopulated(t *testing.T, store *postgres.Store) time.Time {
	t.Helper()
	ctx := context.Background()
	if _, err := store.Pool().Exec(ctx, oldSchemaSQL); err != nil {
		t.Fatalf("old schema: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := store.Pool().Exec(ctx,
		`INSERT INTO workspaces (project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
		 VALUES ('p','w1','w1','w1','team','u1',$1,$1)`, now); err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	if _, err := store.Pool().Exec(ctx,
		`INSERT INTO memberships (project_id, workspace_id, user_id, role, status, created_at, updated_at)
		 VALUES ('p','w1','u1','owner','active',$1,$1)`, now); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return now
}

// TestExpandOnlySteadyStateInterop asserts the rolling-deploy steady state: after
// expand ONLY (no contract), the old narrow PK is still in place (not composite),
// yet writes resolve correctly against the composite UNIQUE INDEX via ON CONFLICT
// — and the cross-tenant id reuse the widening enables only succeeds AFTER
// contract.
func TestExpandOnlySteadyStateInterop(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	now := seedOldPopulated(t, store)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate (expand): %v", err)
	}

	// Expand-only: PK must still be the old narrow one (NOT composite).
	if pkHasTenant(t, store.Pool(), "memberships") {
		t.Fatal("memberships PK is composite after expand-only; contract must not have run")
	}

	// A PutMembership upsert must resolve its ON CONFLICT against the composite
	// unique index even though the PK is still narrow (rolling-deploy interop).
	m := &service.Membership{
		ProjectID: "p", TenantID: "", WorkspaceID: "w1", UserID: "u1",
		Role: service.RoleAdmin, Status: service.StatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.PutMembership(ctx, m); err != nil {
		t.Fatalf("PutMembership upsert against composite unique index: %v", err)
	}

	// EXPAND-ONLY WINDOW: cross-tenant id reuse is NOT yet enabled. The old narrow
	// PK (project_id, id) is still in force, so the same workspace id in a second
	// tenant collides on it — this is exactly why contract is still required.
	ws := func(tenant string) *service.Workspace {
		return &service.Workspace{
			ID: "shared", ProjectID: "p", TenantID: tenant, Slug: "s", DisplayName: "s",
			Type: service.TypeTeam, OwnerUserID: "o", CreatedAt: now, UpdatedAt: now,
		}
	}
	if err := store.CreateWorkspace(ctx, ws("t1")); err != nil {
		t.Fatalf("workspace in t1 (expand-only): %v", err)
	}
	if err := store.CreateWorkspace(ctx, ws("t2")); err == nil {
		t.Fatal("cross-tenant id reuse must NOT be possible in the expand-only window (old narrow PK still in force)")
	}

	// CONTRACT enables cross-tenant id reuse: promoting the composite key to the
	// PK drops the narrow (project_id, id) PK, so the second-tenant insert succeeds.
	if err := store.Contract(ctx); err != nil {
		t.Fatalf("Contract: %v", err)
	}
	if !pkHasTenant(t, store.Pool(), "workspaces") {
		t.Fatal("contract did not make the workspaces PK composite")
	}
	if !pkHasTenant(t, store.Pool(), "memberships") {
		t.Fatal("contract did not make the memberships PK composite")
	}
	if err := store.CreateWorkspace(ctx, ws("t2")); err != nil {
		t.Fatalf("cross-tenant id reuse must succeed after contract: %v", err)
	}
}

// TestContractPendingWarn asserts the migrate_contract_pending WARN fires after
// expand on an UPGRADING (pre-tenant) DB and lists every still-narrow table, and
// does NOT fire on a FRESH (born-composite) DB.
func TestContractPendingWarn(t *testing.T) {
	t.Run("upgrading DB warns", func(t *testing.T) {
		dsn := expandTestDSN(t)
		ctx := context.Background()
		core, logs := observer.New(zap.WarnLevel)
		store, err := postgres.Open(ctx, dsn, postgres.WithLogger(zap.New(core)))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(store.Close)
		seedOldPopulated(t, store)

		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("Migrate (expand): %v", err)
		}
		entries := logs.FilterMessage("migrate_contract_pending").All()
		if len(entries) != 1 {
			t.Fatalf("want exactly one migrate_contract_pending WARN, got %d", len(entries))
		}
		tables, ok := entries[0].ContextMap()["tables"].([]any)
		if !ok || len(tables) == 0 {
			t.Fatalf("WARN missing non-empty tables list: %+v", entries[0].ContextMap())
		}
	})

	t.Run("fresh DB does not warn", func(t *testing.T) {
		dsn := expandTestDSN(t)
		ctx := context.Background()
		core, logs := observer.New(zap.WarnLevel)
		store, err := postgres.Open(ctx, dsn, postgres.WithLogger(zap.New(core)))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(store.Close)

		// Fresh schema: Migrate's CREATE TABLE installs composite PKs directly.
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("Migrate (fresh): %v", err)
		}
		if n := logs.FilterMessage("migrate_contract_pending").Len(); n != 0 {
			t.Fatalf("fresh composite DB must not warn contract-pending, got %d WARNs", n)
		}
	})
}

// TestMigrateDoesNotLeakLockTimeout pins the no-GUC-leak property: because
// migrations run on a DEDICATED connection (not the serving pool), a pooled
// connection used after Migrate reports the DEFAULT lock_timeout (0 = disabled),
// not the 5s the migration sets per session.
func TestMigrateDoesNotLeakLockTimeout(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	seedOldPopulated(t, store)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Exhaust a few pooled connections; none should carry the migration's GUC.
	for i := 0; i < 5; i++ {
		var lockTimeout string
		if err := store.Pool().QueryRow(ctx, "SHOW lock_timeout").Scan(&lockTimeout); err != nil {
			t.Fatalf("SHOW lock_timeout: %v", err)
		}
		if lockTimeout != "0" {
			t.Fatalf("pooled connection carries migration lock_timeout=%q; the GUC leaked off the dedicated migration conn", lockTimeout)
		}
	}
}

// TestMigrationLockBounded asserts the advisory-lock acquisition is bounded:
// when another session holds the migration lock, Migrate fails fast with a clear
// error within a bounded ctx deadline rather than blocking forever.
func TestMigrationLockBounded(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	seedOldPopulated(t, store)

	// Hold the migration advisory lock on a separate dedicated connection.
	holder, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("holder connect: %v", err)
	}
	defer func() { _ = holder.Close(context.Background()) }()
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(0x6D696772)); err != nil {
		t.Fatalf("hold lock: %v", err)
	}

	// Migrate under a short deadline must return (fail fast), not hang.
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Migrate(bounded) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Migrate succeeded while the lock was held; expected a fail-fast error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Migrate hung on the advisory lock instead of failing fast under the bounded ctx")
	}
}

// TestMigrateIgnoresSameNamedIndexInOtherSchema pins the schema-qualification
// fix: a workspaces_personal_uniq index in a DIFFERENT schema of the same
// database must not trigger or abort the migration's drop-stale-index block.
func TestMigrateIgnoresSameNamedIndexInOtherSchema(t *testing.T) {
	dsn := testPostgresDSN(t)
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
