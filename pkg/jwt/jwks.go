package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// jwksVerifier verifies RS256 tokens against identity's published JWKS,
// caching keys by `kid` and refetching on cache miss (a key rotation).
type jwksVerifier struct {
	url    string
	issuer string
	client *http.Client

	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	fetched  time.Time
	minRetry time.Duration
}

// NewJWKSVerifier verifies RS256 tokens signed by the keys served at
// jwksURL (identity's /.well-known/jwks.json).
func NewJWKSVerifier(jwksURL, issuer string) Verifier {
	return &jwksVerifier{
		url:      jwksURL,
		issuer:   issuer,
		client:   &http.Client{Timeout: 5 * time.Second},
		keys:     map[string]*rsa.PublicKey{},
		minRetry: 10 * time.Second,
	}
}

func (v *jwksVerifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := gojwt.Parse(raw, func(t *gojwt.Token) (any, error) {
		if _, ok := t.Method.(*gojwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		key, err := v.keyByID(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}, gojwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claimsFrom(tok, v.issuer)
}

func (v *jwksVerifier) keyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[kid]
	stale := time.Since(v.fetched) > v.minRetry
	v.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if !stale {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if key := v.keys[kid]; key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown kid %q after refresh", kid)
}

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *jwksVerifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSA(k.N, k.E)
		if err != nil {
			return fmt.Errorf("jwks key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func parseRSA(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
