package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func do(t *testing.T, h http.Handler, method, path, authz string) int {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestServiceAuthEnforced(t *testing.T) {
	h := ServiceAuth([]string{"secret-a", "secret-b"}, nil, nil)(okHandler())

	if code := do(t, h, http.MethodPost, "/workspace.v1.AuthzService/Check", "Bearer secret-a"); code != http.StatusOK {
		t.Fatalf("valid token a: got %d", code)
	}
	if code := do(t, h, http.MethodPost, "/workspace.v1.AuthzService/Check", "Bearer secret-b"); code != http.StatusOK {
		t.Fatalf("valid token b: got %d", code)
	}
	if code := do(t, h, http.MethodPost, "/workspace.v1.AuthzService/Check", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", code)
	}
	if code := do(t, h, http.MethodPost, "/workspace.v1.AuthzService/Check", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", code)
	}
}

func TestServiceAuthBypassesInfraAndPreflight(t *testing.T) {
	h := ServiceAuth([]string{"secret"}, nil, nil)(okHandler())

	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		if code := do(t, h, http.MethodGet, p, ""); code != http.StatusOK {
			t.Fatalf("infra path %s should bypass auth: got %d", p, code)
		}
	}
	if code := do(t, h, http.MethodOptions, "/workspace.v1.AuthzService/Check", ""); code != http.StatusOK {
		t.Fatalf("preflight should bypass auth: got %d", code)
	}
}

func TestServiceAuthDisabledWhenNoTokens(t *testing.T) {
	h := ServiceAuth(nil, nil, nil)(okHandler())
	if code := do(t, h, http.MethodPost, "/workspace.v1.AuthzService/Check", ""); code != http.StatusOK {
		t.Fatalf("no tokens configured should allow all: got %d", code)
	}
}
