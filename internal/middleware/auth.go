package middleware

import (
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/workspaces/internal/service"
	"github.com/elloloop/workspaces/pkg/jwt"
)

// Auth verifies the bearer token on each request and, on success, attaches
// the resulting Principal to the context. It never rejects outright: a
// missing/invalid token simply leaves no principal, so unauthenticated
// infrastructure routes (health, metrics) still pass while RPC handlers
// reject via the absent principal. The token's project_id claim selects the
// shard; an empty claim falls back to the configured default project.
func Auth(verifier jwt.Verifier, defaultProjectID string, logger *zap.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r.Header.Get("Authorization"))
			if raw == "" {
				next.ServeHTTP(w, r)
				return
			}
			claims, err := verifier.Verify(r.Context(), raw)
			if err != nil {
				logger.Debug("token_verification_failed", zap.Error(err))
				next.ServeHTTP(w, r)
				return
			}
			projectID := claims.ProjectID
			if projectID == "" {
				projectID = defaultProjectID
			}
			p := service.Principal{UserID: claims.UserID, ProjectID: projectID}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
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
