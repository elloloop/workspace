package middleware

import (
	"context"

	"github.com/elloloop/workspaces/internal/service"
)

type principalKey struct{}

// WithPrincipal returns a context carrying the authenticated caller.
func WithPrincipal(ctx context.Context, p service.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated caller, or ok=false if the request
// was not authenticated (the auth middleware did not run / rejected it).
func PrincipalFrom(ctx context.Context) (service.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(service.Principal)
	return p, ok
}
