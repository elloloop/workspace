package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// ServiceAuth authenticates the CALLING SERVICE, not an end user. This is an
// internal service: trusted product backends present a shared service
// credential as `Authorization: Bearer <token>`; the end user is passed as
// data in the request body (acting_user_id / subject_user_id), Zanzibar
// style. End-user authentication happens at the product edge, before this
// service is called.
//
// When no tokens are configured, the requirement is disabled and every
// caller is trusted — appropriate only behind a service mesh / mTLS / a
// private network. A loud warning is logged at construction so this is never
// silent. Infrastructure routes (health, metrics) and CORS preflights always
// bypass the check.
// creds are an OPTIONAL typed mapping: a matching credential authenticates AND
// carries a named CallerIdentity (with an optional project pin) into the request
// context. The flat tokens still authenticate with an anonymous identity, so the
// mapping is purely additive — existing GATEWAY_SERVICE_AUTH_TOKENS deployments
// are unchanged. A credential's token is also a valid token, so the two lists
// may overlap; the credential wins (it carries identity).
func ServiceAuth(tokens []string, creds []ServiceCredential, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	tokens = nonEmpty(tokens)
	if len(tokens) == 0 && len(creds) == 0 {
		logger.Warn("service_auth_disabled",
			zap.String("reason", "no GATEWAY_SERVICE_AUTH_TOKENS or GATEWAY_SERVICE_CREDENTIALS configured"),
			zap.String("impact", "all callers trusted — deploy behind a private network/mesh or set the tokens"))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if (len(tokens) == 0 && len(creds) == 0) || IsInfraPath(r.URL.Path) || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			presented := bearerToken(r.Header.Get("Authorization"))
			if c, ok := matchCredential(presented, creds); ok {
				next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), c)))
				return
			}
			if tokenMatches(presented, tokens) {
				next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), CallerIdentity{})))
				return
			}
			// Bare 401: Connect maps it to CodeUnauthenticated for the client.
			http.Error(w, "invalid service credentials", http.StatusUnauthorized)
		})
	}
}

// matchCredential returns the CallerIdentity for a presented credential, using a
// constant-time compare against every entry so a timing side-channel can't leak
// a token. An empty presented value never matches.
func matchCredential(presented string, creds []ServiceCredential) (CallerIdentity, bool) {
	if presented == "" {
		return CallerIdentity{}, false
	}
	match := CallerIdentity{}
	found := false
	for _, c := range creds {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(c.Token)) == 1 {
			match = CallerIdentity{Name: c.Name, ProjectID: c.ProjectID}
			found = true
		}
	}
	return match, found
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

// tokenMatches reports whether presented equals any configured token, using a
// constant-time comparison so a timing side-channel can't leak the secret.
func tokenMatches(presented string, tokens []string) bool {
	if presented == "" {
		return false
	}
	ok := false
	for _, t := range tokens {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(t)) == 1 {
			ok = true
		}
	}
	return ok
}

func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
