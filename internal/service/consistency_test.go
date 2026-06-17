package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/workspace/internal/consistencytoken"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

func TestEnsureConsistency(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()
	p := service.Principal{ProjectID: "p", TenantID: "t"}

	// A write returns a token; a read carrying it is satisfied (read-after-write).
	token, err := svc.WriteTuples(ctx, p, []service.TupleOp{
		{Tuple: authz.Tuple{Namespace: "doc", ObjectID: "d1", Relation: "viewer", Subject: authz.Subject{UserID: "u1"}}},
	})
	if err != nil || token == "" {
		t.Fatalf("WriteTuples = (%q, %v)", token, err)
	}
	if err := svc.EnsureConsistency(ctx, p, token); err != nil {
		t.Fatalf("own token must be satisfied: %v", err)
	}

	// Empty token is a no-op.
	if err := svc.EnsureConsistency(ctx, p, ""); err != nil {
		t.Fatalf("empty token must be a no-op: %v", err)
	}

	// Malformed token → ErrInvalidArgument.
	if err := svc.EnsureConsistency(ctx, p, "garbage"); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("malformed token err = %v, want ErrInvalidArgument", err)
	}

	// A token for a different shard → ErrInvalidArgument.
	foreign := consistencytoken.Encode("other", "t", 1)
	if err := svc.EnsureConsistency(ctx, p, foreign); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("foreign-shard token err = %v, want ErrInvalidArgument", err)
	}

	// A token demanding an unreached sequence (forged/future) → ErrFailedPrecondition.
	future := consistencytoken.Encode("p", "t", 9999)
	if err := svc.EnsureConsistency(ctx, p, future); !errors.Is(err, service.ErrFailedPrecondition) {
		t.Fatalf("unreached-seq token err = %v, want ErrFailedPrecondition", err)
	}
}
