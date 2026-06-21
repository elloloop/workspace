package postgres_test

import (
	"context"
	"testing"

	"github.com/elloloop/workspace/internal/repo/conformance"
	"github.com/elloloop/workspace/internal/repo/postgres"
	"github.com/elloloop/workspace/internal/service"
)

// TestPostgresConformance runs the shared suite against a real Postgres. It
// skips unless a DSN is set via WORKSPACES_TEST_POSTGRES_DSN (local) or
// GATEWAY_TEST_POSTGRES_DSN (the name CI's coverage job provides).
func TestPostgresConformance(t *testing.T) {
	dsn := testPostgresDSN(t)
	ctx := context.Background()
	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	conformance.Run(t, func() service.Repository {
		// Each Run gets a clean slate by truncating every table.
		_, err := store.Pool().Exec(ctx,
			`TRUNCATE workspaces, memberships, invitations, groups, relation_tuples,
				consistency_seq, enrollments, seat_limits, seat_assignments`)
		if err != nil {
			t.Fatalf("TRUNCATE: %v", err)
		}
		return store
	})
}
