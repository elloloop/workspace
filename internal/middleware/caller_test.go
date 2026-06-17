package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureCaller runs the middleware and returns the resolved CallerIdentity (and
// HTTP status) for a presented bearer token.
func captureCaller(t *testing.T, mw func(http.Handler) http.Handler, token string) (int, CallerIdentity) {
	t.Helper()
	var got CallerIdentity
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = CallerFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/workspace.v1.AuthzService/Check", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, got
}

func TestServiceAuthResolvesCredentialIdentity(t *testing.T) {
	creds := []ServiceCredential{
		{Token: "slack-token", Name: "slack", ProjectID: "slack-proj"},
		{Token: "linear-token", Name: "linear"}, // no project pin
	}
	mw := ServiceAuth([]string{"flat-token"}, creds, nil)

	// A mapped credential authenticates AND carries its identity + project pin.
	if code, c := captureCaller(t, mw, "slack-token"); code != http.StatusOK || c.Name != "slack" || c.ProjectID != "slack-proj" {
		t.Fatalf("slack credential: code=%d caller=%+v", code, c)
	}
	// A mapped credential without a pin: named, no project.
	if code, c := captureCaller(t, mw, "linear-token"); code != http.StatusOK || c.Name != "linear" || c.ProjectID != "" {
		t.Fatalf("linear credential: code=%d caller=%+v", code, c)
	}
	// A legacy flat token still authenticates, with an anonymous identity.
	if code, c := captureCaller(t, mw, "flat-token"); code != http.StatusOK || c != (CallerIdentity{}) {
		t.Fatalf("flat token: code=%d caller=%+v (want 200 + anonymous)", code, c)
	}
	// An unknown credential is rejected.
	if code, _ := captureCaller(t, mw, "nope"); code != http.StatusUnauthorized {
		t.Fatalf("unknown credential: code=%d, want 401", code)
	}
}

// TestServiceAuthCredentialsOnly: a deployment configured ONLY with credentials
// (no flat tokens) still enforces auth.
func TestServiceAuthCredentialsOnly(t *testing.T) {
	mw := ServiceAuth(nil, []ServiceCredential{{Token: "only", Name: "svc"}}, nil)
	if code, c := captureCaller(t, mw, "only"); code != http.StatusOK || c.Name != "svc" {
		t.Fatalf("credential-only auth: code=%d caller=%+v", code, c)
	}
	if code, _ := captureCaller(t, mw, "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("credential-only auth, wrong token: code=%d, want 401", code)
	}
}
