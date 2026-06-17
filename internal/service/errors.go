package service

import (
	"errors"
	"fmt"
)

// Sentinel errors the service layer returns; the Connect handlers map each
// to a wire status code (see internal/connect).
var (
	ErrNotFound           = errors.New("not found")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidArgument    = errors.New("invalid argument")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrFailedPrecondition = errors.New("failed precondition")
	ErrResourceExhausted  = errors.New("resource exhausted")
	// ErrRegionNotServable is the specific failed-precondition raised when this
	// instance's data region differs from a project's pinned region. It wraps
	// ErrFailedPrecondition (so it maps to the same wire code) but is
	// distinguishable via errors.Is for telemetry (a residency refusal is not a
	// generic precondition failure).
	ErrRegionNotServable = fmt.Errorf("%w: data region not servable by this instance", ErrFailedPrecondition)
)
