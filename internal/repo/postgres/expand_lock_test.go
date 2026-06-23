package postgres_test

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/repo/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// expandTestDSN returns a DSN whose search_path points at a freshly-created,
// isolated schema (ws_wt33_<rand>), so the test never touches public. The schema
// is created as identity/identity and dropped on cleanup. It skips when no test
// Postgres DSN is configured.
func expandTestDSN(t *testing.T) string {
	t.Helper()
	base := testPostgresDSN(t)

	schema := fmt.Sprintf("ws_wt33_%d", rand.Int63()) //nolint:gosec // test schema name, not security-sensitive
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	admin.Close()
	t.Cleanup(func() {
		ctx := context.Background()
		a, err := pgxpool.New(ctx, base)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	q := u.Query()
	// Pin every connection in the pool to the isolated schema only.
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// seedOldSchema stands up the pre-tenant single-column-PK schema in the current
// (isolated) schema and seeds n workspace rows so the table is non-empty during
// expand. It returns the DSN's pool for second-connection assertions.
func seedOldWorkspaces(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	ctx := context.Background()
	old := strings.Replace(oldSchemaSQL,
		"DROP TABLE IF EXISTS projects, workspaces, memberships, invitations, groups, relation_tuples CASCADE;",
		"", 1)
	if _, err := pool.Exec(ctx, old); err != nil {
		t.Fatalf("old schema: %v", err)
	}
	// Pre-add the tenant_id column so the base schemaSQL (CREATE TABLE IF NOT
	// EXISTS + ADD COLUMN IF NOT EXISTS) is a pure no-op during the measured
	// expand window — matching the real upgrade where the prior boot already
	// added the column. This isolates the lock assertion to the CONCURRENTLY
	// composite-index build, which is the step that must not take a long lock.
	if _, err := pool.Exec(ctx,
		`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT ''`); err != nil {
		t.Fatalf("pre-add tenant_id: %v", err)
	}
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO workspaces (project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
			 VALUES ('p',$1,$1,$1,'team',$1,$2,$2)`,
			fmt.Sprintf("w%d", i), now); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
}

// TestExpandHoldsNoAccessExclusiveLock proves the acceptance criterion: building
// the composite key during expand on a POPULATED table takes NO long ACCESS
// EXCLUSIVE lock. A second connection (a) polls pg_locks for an
// AccessExclusiveLock on workspaces and (b) runs concurrent INSERTs, asserting
// both that the lock never appears and that the writes complete promptly.
func TestExpandHoldsNoAccessExclusiveLock(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	pool := store.Pool()

	seedOldWorkspaces(t, pool, 2000)

	// Observer pool on a separate connection set, polling locks + writing rows
	// while expand runs.
	obs, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("observer pool: %v", err)
	}
	defer obs.Close()

	stop := make(chan struct{})
	// We assert no LONG ACCESS EXCLUSIVE hold. A CONCURRENTLY index build never
	// takes ACCESS EXCLUSIVE at all; the only legitimate ACCESS EXCLUSIVE during
	// expand is the personal-index swap's DROP+RENAME, a size-INDEPENDENT metadata
	// op held for a few milliseconds. A regression to an in-place rebuild (or the
	// old whole-schema-in-one-transaction approach) would instead hold the lock
	// for a data-proportional duration. So we measure the CONTIGUOUS wall-clock
	// hold and flag only a hold far longer than any metadata flick — robust to a
	// slow/contended CI runner stretching a brief metadata lock across several
	// poll iterations (which a fixed consecutive-count would false-positive on).
	const maxContiguousHold = 400 * time.Millisecond
	longAccessExclusive := make(chan bool, 1)
	go func() {
		var heldSince time.Time // zero when the lock is not currently held
		longHeld := false
		for {
			select {
			case <-stop:
				longAccessExclusive <- longHeld
				return
			default:
			}
			var present bool
			err := obs.QueryRow(context.Background(),
				`SELECT EXISTS (
					SELECT 1 FROM pg_locks l
					 WHERE l.relation = to_regclass(current_schema() || '.workspaces')
					   AND l.mode = 'AccessExclusiveLock' AND l.granted)`).Scan(&present)
			switch {
			case err == nil && present:
				if heldSince.IsZero() {
					heldSince = time.Now()
				} else if time.Since(heldSince) > maxContiguousHold {
					longHeld = true
				}
			default:
				heldSince = time.Time{} // released (or a transient poll error): reset
			}
			time.Sleep(time.Millisecond)
		}
	}()

	// Concurrent writes during expand must NOT be blocked: each must complete
	// well within the 5s migration lock_timeout (a real ACCESS EXCLUSIVE hold
	// would queue them behind it). A bounded per-insert context is the robust
	// block detector: under a CONCURRENTLY build every insert returns promptly,
	// whereas a sustained ACCESS EXCLUSIVE would queue an insert until the context
	// deadline (failing the test) — without relying on a wall-clock latency
	// threshold that a slow CI runner could trip on an unblocked insert.
	writesOK := make(chan error, 1)
	go func() {
		now := time.Now().UTC()
		for i := 0; i < 50; i++ {
			select {
			case <-stop:
				writesOK <- nil
				return
			default:
			}
			ctxW, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := obs.Exec(ctxW,
				`INSERT INTO workspaces (project_id, id, slug, display_name, type, owner_user_id, created_at, updated_at)
				 VALUES ('p',$1,$1,$1,'team',$1,$2,$2)`,
				fmt.Sprintf("live%d", i), now)
			cancel()
			if err != nil {
				writesOK <- fmt.Errorf("concurrent insert %d blocked/failed (expand took a long lock?): %w", i, err)
				return
			}
		}
		writesOK <- nil
	}()

	if err := store.Migrate(ctx); err != nil {
		close(stop)
		t.Fatalf("Migrate (expand): %v", err)
	}
	close(stop)

	if err := <-writesOK; err != nil {
		t.Fatal(err)
	}
	if long := <-longAccessExclusive; long {
		t.Fatal("expand held a sustained AccessExclusiveLock on the populated workspaces table")
	}

	// The composite unique index must now exist and be valid, with the old PK
	// still intact (expand does not drop it).
	assertCompositeIndexValid(t, pool, "workspaces_pk_tenant")
	if !pkExists(t, pool, "workspaces_pkey") {
		t.Fatal("expand dropped the old PK; it must stay intact for rolling-deploy interop")
	}
}

// TestExpandIsIdempotent asserts a second expand on an already-expanded table is
// a clean no-op.
func TestExpandIsIdempotent(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	seedOldWorkspaces(t, store.Pool(), 100)
	for i := 0; i < 3; i++ {
		if err := store.Migrate(ctx); err != nil {
			t.Fatalf("Migrate run %d: %v", i, err)
		}
	}
	assertCompositeIndexValid(t, store.Pool(), "workspaces_pk_tenant")
}

// TestContractPromotesToPrimaryKey asserts contract promotes the composite index
// to the PRIMARY KEY (including tenant_id) and is idempotent.
func TestContractPromotesToPrimaryKey(t *testing.T) {
	dsn := expandTestDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	pool := store.Pool()
	seedOldWorkspaces(t, pool, 100)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate (expand): %v", err)
	}
	// Before contract: old narrow PK still in place.
	if pkHasTenant(t, pool, "workspaces") {
		t.Fatal("PK already composite before contract")
	}
	for i := 0; i < 2; i++ {
		if err := store.Contract(ctx); err != nil {
			t.Fatalf("Contract run %d: %v", i, err)
		}
	}
	if !pkHasTenant(t, pool, "workspaces") {
		t.Fatal("contract did not promote the composite key to the PRIMARY KEY")
	}
}

func assertCompositeIndexValid(t *testing.T, pool *pgxpool.Pool, idx string) {
	t.Helper()
	var valid bool
	err := pool.QueryRow(context.Background(),
		`SELECT i.indisvalid FROM pg_index i
		  WHERE i.indexrelid = to_regclass(current_schema() || '.' || $1)`, idx).Scan(&valid)
	if err != nil {
		t.Fatalf("index %s state: %v", idx, err)
	}
	if !valid {
		t.Fatalf("composite index %s is not valid", idx)
	}
}

func pkExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT to_regclass(current_schema() || '.' || $1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("pk %s lookup: %v", name, err)
	}
	return exists
}

func pkHasTenant(t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var has bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (
			SELECT 1 FROM pg_index i
			  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
			 WHERE i.indrelid = to_regclass(current_schema() || '.' || $1)
			   AND i.indisprimary AND a.attname = 'tenant_id')`, table).Scan(&has); err != nil {
		t.Fatalf("pk-has-tenant %s: %v", table, err)
	}
	return has
}
