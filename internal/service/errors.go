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

// HasControlChar reports whether s contains any ASCII control character
// (byte < 0x20, which includes NUL). It is the single source of truth for the
// storage-key invariant: ids and tuple fields are joined into in-memory keys
// with separators (project+"\x00"+tenant; tuple fields with '|' and '/'), so a
// control char inside a field is never legitimate and could forge a separator.
// Scope-id validation (connect handler), project-id validation (CreateProject/
// UpdateProject), and tuple-field validation (validateTuple) all share this one
// rule — do not reimplement the byte loop elsewhere.
func HasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}
