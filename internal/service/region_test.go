package service_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// TestEnsureDefaultProjectRegionFailFast: an instance must refuse to boot
// against a default project pinned to a different region than it serves.
func TestEnsureDefaultProjectRegionFailFast(t *testing.T) {
	repo := memory.New()
	ctx := context.Background()

	// A us-east-1 instance seeds the default project pinned to its region.
	east := service.New(repo, nil, nil, service.WithDataRegion("us-east-1"))
	if err := east.EnsureDefaultProject(ctx, "default"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := east.GetProject(ctx, "default")
	if err != nil || got.DataRegion != "us-east-1" {
		t.Fatalf("seeded default region = %+v, %v; want us-east-1", got, err)
	}

	// A different-region instance against the SAME store must fail fast.
	west := service.New(repo, nil, nil, service.WithDataRegion("eu-west-1"))
	if err := west.EnsureDefaultProject(ctx, "default"); !errors.Is(err, service.ErrFailedPrecondition) {
		t.Fatalf("mismatched-region boot = %v, want ErrFailedPrecondition", err)
	}
	// A matching-region instance boots fine (idempotent).
	if err := east.EnsureDefaultProject(ctx, "default"); err != nil {
		t.Fatalf("matching-region re-boot: %v", err)
	}
}

// TestUpdateProjectClearAndRepin: a pinned region can be cleared back to
// region-agnostic via clear_data_region, and a repin to a region this instance
// does not serve logs an operability warning.
func TestUpdateProjectClearAndRepin(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	svc := service.New(memory.New(), nil, nil,
		service.WithDataRegion("us-east-1"), service.WithLogger(zap.New(core)))
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "p", "P", nil, "us-east-1"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	// Clear the pin → region-agnostic.
	got, err := svc.UpdateProject(ctx, "p", "", "", nil, "", true)
	if err != nil || got.DataRegion != "" {
		t.Fatalf("clear pin = %+v, %v; want empty region", got, err)
	}

	// clear + a region value is a contradiction.
	if _, err := svc.UpdateProject(ctx, "p", "", "", nil, "eu-west-1", true); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("clear+region = %v, want ErrInvalidArgument", err)
	}

	// Repin to a region this instance does NOT serve → succeeds but warns.
	if _, err := svc.UpdateProject(ctx, "p", "", "", nil, "eu-west-1", false); err != nil {
		t.Fatalf("repin: %v", err)
	}
	if logs.FilterMessage("data_region_repin_unservable_here").Len() == 0 {
		t.Fatal("a repin to an unservable region must log a breadcrumb")
	}
}

// TestRegionRefusalWarns: a mis-routed request is refused with
// ErrRegionNotServable and leaves a structured warn breadcrumb.
func TestRegionRefusalWarns(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	svc := service.New(memory.New(), nil, nil,
		service.WithDataRegion("us-east-1"), service.WithLogger(zap.New(core)))
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "eu", "EU", nil, "eu-west-1"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	err := svc.EnsureServable(ctx, service.Principal{ProjectID: "eu"})
	if !errors.Is(err, service.ErrRegionNotServable) {
		t.Fatalf("mis-routed = %v, want ErrRegionNotServable", err)
	}
	if !errors.Is(err, service.ErrFailedPrecondition) {
		t.Fatal("ErrRegionNotServable must wrap ErrFailedPrecondition (same wire code)")
	}
	if logs.FilterMessage("data_region_refused").Len() == 0 {
		t.Fatal("a residency refusal must log a breadcrumb")
	}
	// A matching-region project is servable.
	if _, err := svc.CreateProject(ctx, "us", "US", nil, "us-east-1"); err != nil {
		t.Fatalf("CreateProject us: %v", err)
	}
	if err := svc.EnsureServable(ctx, service.Principal{ProjectID: "us"}); err != nil {
		t.Fatalf("matching region must be servable: %v", err)
	}
}
