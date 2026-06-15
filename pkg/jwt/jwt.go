// Package jwt verifies the access tokens minted by the identity service
// (github.com/elloloop/identity). The workspace service never issues
// tokens; it only consumes them. A token's `sub` is the user id every
// authorization decision is made against, and an optional `project_id`
// claim selects the isolation shard (identity ADR-0002).
//
// Two verifiers ship: an HS256 verifier for tests and shared-secret
// deployments, and a JWKS verifier that fetches identity's
// `/.well-known/jwks.json` for production RS256 tokens.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Claims is the verified subset of a token the service acts on.
type Claims struct {
	UserID    string
	ProjectID string
	Issuer    string
}

// Verifier validates a raw bearer token and returns its claims.
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Claims, error)
}

// ErrInvalidToken is returned for any token that fails verification. The
// concrete reason is wrapped for logs but not exposed to callers, so a
// probing client cannot distinguish "expired" from "bad signature".
var ErrInvalidToken = errors.New("invalid token")

func claimsFrom(tok *gojwt.Token, wantIssuer string) (*Claims, error) {
	mc, ok := tok.Claims.(gojwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected claims type", ErrInvalidToken)
	}
	sub, _ := mc["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	iss, _ := mc["iss"].(string)
	if wantIssuer != "" && iss != wantIssuer {
		return nil, fmt.Errorf("%w: issuer %q != %q", ErrInvalidToken, iss, wantIssuer)
	}
	projectID, _ := mc["project_id"].(string)
	return &Claims{UserID: sub, ProjectID: projectID, Issuer: iss}, nil
}

// ── HS256 ───────────────────────────────────────────────────────────────

type hs256Verifier struct {
	secret []byte
	issuer string
}

// NewHS256Verifier verifies HMAC-SHA-256 tokens against a shared secret.
func NewHS256Verifier(secret, issuer string) Verifier {
	return &hs256Verifier{secret: []byte(secret), issuer: issuer}
}

func (v *hs256Verifier) Verify(_ context.Context, raw string) (*Claims, error) {
	tok, err := gojwt.Parse(raw, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return v.secret, nil
	}, gojwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claimsFrom(tok, v.issuer)
}

// MintHS256 issues a token — used by tests and by tooling that needs to
// stand in for identity. Production tokens come from identity, not here.
func MintHS256(secret, issuer, userID, projectID string, ttl time.Duration) (string, error) {
	claims := gojwt.MapClaims{
		"sub": userID,
		"iss": issuer,
		"exp": time.Now().Add(ttl).Unix(),
		"iat": time.Now().Unix(),
	}
	if projectID != "" {
		claims["project_id"] = projectID
	}
	return gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}
