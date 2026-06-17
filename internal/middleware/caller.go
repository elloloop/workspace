package middleware

import "context"

// CallerIdentity is the resolved identity of the CALLING SERVICE (not the end
// user, who is always request data). It is empty/anonymous for a legacy flat
// service token and populated for a credential mapped via ServiceCredentials.
type CallerIdentity struct {
	// Name is the integration/service principal id (e.g. "slack", "linear"),
	// for attribution and auditing. Empty for an anonymous (flat-token) caller.
	Name string
	// ProjectID, when non-empty, pins the caller to a project: every request it
	// makes is forced into this project regardless of the request's project_id,
	// so an integration cannot operate outside its assigned project.
	ProjectID string
}

// ServiceCredential maps one accepted service credential to a calling-service
// identity (and optional project pin). It is the typed form of an entry in
// GATEWAY_SERVICE_CREDENTIALS.
type ServiceCredential struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	ProjectID string `json:"project,omitempty"`
}

type callerCtxKey struct{}

// WithCaller returns a context carrying the resolved calling-service identity.
func WithCaller(ctx context.Context, c CallerIdentity) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// CallerFrom returns the calling-service identity resolved by ServiceAuth, or a
// zero CallerIdentity for an anonymous/unauthenticated-but-trusted caller.
func CallerFrom(ctx context.Context) CallerIdentity {
	if c, ok := ctx.Value(callerCtxKey{}).(CallerIdentity); ok {
		return c
	}
	return CallerIdentity{}
}
