package postgres_test

import (
	"context"
	"os"
	"testing"

	"github.com/elloloop/workspaces/internal/repo/conformance"
	"github.com/elloloop/workspaces/internal/repo/postgres"
	"github.com/elloloop/workspaces/internal/service"
)

// TestPostgresConformance runs the shared suite against a real Postgres.
// It skips unless WORKSPACES_TEST_POSTGRES_DSN points at a database.
func TestPostgresConformance(t *testing.T) {
	dsn := os.Getenv("WORKSPACES_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set WORKSPACES_TEST_POSTGRES_DSN to run the Postgres conformance suite")
	}

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
			`TRUNCATE workspaces, memberships, invitations, groups, relation_tuples`)
		if err != nil {
			t.Fatalf("TRUNCATE: %v", err)
		}
		return store
	})
}
