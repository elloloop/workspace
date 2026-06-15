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
func ServiceAuth(tokens []string, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	tokens = nonEmpty(tokens)
	if len(tokens) == 0 {
		logger.Warn("service_auth_disabled",
			zap.String("reason", "no GATEWAY_SERVICE_AUTH_TOKENS configured"),
			zap.String("impact", "all callers trusted — deploy behind a private network/mesh or set the tokens"))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) == 0 || IsInfraPath(r.URL.Path) || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if !tokenMatches(bearerToken(r.Header.Get("Authorization")), tokens) {
				// Bare 401: Connect maps it to CodeUnauthenticated for the client.
				http.Error(w, "invalid service credentials", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
