package service

import "errors"

// Sentinel errors the service layer returns; the Connect handlers map each
// to a wire status code (see internal/connect).
var (
	ErrNotFound           = errors.New("not found")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidArgument    = errors.New("invalid argument")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrFailedPrecondition = errors.New("failed precondition")
)
