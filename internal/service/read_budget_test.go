package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/workspace/internal/config"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// TestCreateProjectMaxCheckReads_RoundTrip: a project created with a per-project
// max_check_reads override reads it back on GetProject and ListProjects.
func TestCreateProjectMaxCheckReads_RoundTrip(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "p", "P", nil, "", 750); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	got, err := svc.GetProject(ctx, "p")
	if err != nil || got.MaxCheckReads != 750 {
		t.Fatalf("GetProject budget = %+v, %v; want 750", got, err)
	}
	list, err := svc.ListProjects(ctx)
	if err != nil || len(list) != 1 || list[0].MaxCheckReads != 750 {
		t.Fatalf("ListProjects = %+v, %v; want one project with budget 750", list, err)
	}
}

// TestCreateProjectMaxCheckReads_RejectsSubFloor: a small-positive override
// (below the shared floor) is rejected; 0 (the global default) is accepted.
func TestCreateProjectMaxCheckReads_RejectsSubFloor(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "bad", "B", nil, "", config.MinMaxCheckReads-1); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("sub-floor override = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.CreateProject(ctx, "ok", "O", nil, "", 0); err != nil {
		t.Fatalf("zero override (global default) must be accepted, got %v", err)
	}
	if _, err := svc.CreateProject(ctx, "floor", "F", nil, "", config.MinMaxCheckReads); err != nil {
		t.Fatalf("at-floor override must be accepted, got %v", err)
	}
}

// TestUpdateProjectMaxCheckReads_SetAndClear: an override can be set on Update,
// and cleared back to the global default via clear_max_check_reads.
func TestUpdateProjectMaxCheckReads_SetAndClear(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "p", "P", nil, "", 0); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	// Set an override.
	got, err := svc.UpdateProject(ctx, "p", "", "", nil, "", false, 1000, false)
	if err != nil || got.MaxCheckReads != 1000 {
		t.Fatalf("set override = %+v, %v; want 1000", got, err)
	}
	// 0 leaves it unchanged.
	got, err = svc.UpdateProject(ctx, "p", "", "", nil, "", false, 0, false)
	if err != nil || got.MaxCheckReads != 1000 {
		t.Fatalf("zero leaves override unchanged = %+v, %v; want 1000", got, err)
	}
	// Clear resets to the global default (0).
	got, err = svc.UpdateProject(ctx, "p", "", "", nil, "", false, 0, true)
	if err != nil || got.MaxCheckReads != 0 {
		t.Fatalf("clear override = %+v, %v; want 0", got, err)
	}
	// clear + a positive value is a contradiction.
	if _, err := svc.UpdateProject(ctx, "p", "", "", nil, "", false, 1000, true); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("clear+value = %v, want ErrInvalidArgument", err)
	}
	// A sub-floor override on Update is rejected too.
	if _, err := svc.UpdateProject(ctx, "p", "", "", nil, "", false, config.MinMaxCheckReads-1, false); !errors.Is(err, service.ErrInvalidArgument) {
		t.Fatalf("sub-floor update = %v, want ErrInvalidArgument", err)
	}
}

// TestMaxCheckReads_PerProjectIsolation: project A's override does not affect
// project B (B keeps the global default of 0).
func TestMaxCheckReads_PerProjectIsolation(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	if _, err := svc.CreateProject(ctx, "a", "A", nil, "", 1234); err != nil {
		t.Fatalf("CreateProject a: %v", err)
	}
	if _, err := svc.CreateProject(ctx, "b", "B", nil, "", 0); err != nil {
		t.Fatalf("CreateProject b: %v", err)
	}
	a, _ := svc.GetProject(ctx, "a")
	b, _ := svc.GetProject(ctx, "b")
	if a.MaxCheckReads != 1234 || b.MaxCheckReads != 0 {
		t.Fatalf("isolation broken: a=%d b=%d; want 1234 / 0", a.MaxCheckReads, b.MaxCheckReads)
	}
}
