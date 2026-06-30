package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCORS pins the exact-match allowlist, "*" wildcard, preflight short-circuit,
// and the no-Origin / disallowed-origin paths that leave no CORS headers.
func TestCORS(t *testing.T) {
	const origin = "https://app.example.com"

	t.Run("matching origin echoes origin and sets Vary", func(t *testing.T) {
		nextCalled := false
		h := CORS([]string{origin})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if !nextCalled {
			t.Fatal("non-OPTIONS request must reach the next handler")
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("Allow-Origin = %q, want %q", got, origin)
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("Vary = %q, want Origin", got)
		}
	})

	t.Run("wildcard allows any origin as *", func(t *testing.T) {
		h := CORS([]string{"*"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Origin", "https://anything.test")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("Allow-Origin = %q, want *", got)
		}
		if got := rec.Header().Get("Vary"); got != "" {
			t.Fatalf("wildcard must not set Vary, got %q", got)
		}
	})

	t.Run("disallowed origin gets no CORS headers", func(t *testing.T) {
		h := CORS([]string{origin})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("disallowed origin must not get Allow-Origin, got %q", got)
		}
	})

	t.Run("no Origin header gets no CORS headers", func(t *testing.T) {
		h := CORS([]string{origin})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("absent Origin must not get Allow-Origin, got %q", got)
		}
	})

	t.Run("OPTIONS preflight short-circuits with 204", func(t *testing.T) {
		nextCalled := false
		h := CORS([]string{origin})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
		}))
		req := httptest.NewRequest(http.MethodOptions, "/x", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if nextCalled {
			t.Fatal("OPTIONS preflight must not reach the next handler")
		}
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want %d", rec.Code, http.StatusNoContent)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Fatal("preflight must set Allow-Methods for the allowed origin")
		}
	})
}

func TestSanitizeLogValue(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "/workspace.v1.AuthzService/Check", "/workspace.v1.AuthzService/Check"},
		{"newline forged entry", "/x\nERROR forged log line", "/x_ERROR forged log line"},
		{"carriage return", "/a\r\nb", "/a__b"},
		{"tab and del", "/a\tb\x7f", "/a_b_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeLogValue(c.in); got != c.want {
				t.Fatalf("sanitizeLogValue(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSanitizeLogValueBoundsLength(t *testing.T) {
	got := sanitizeLogValue(strings.Repeat("a", 1000))
	if len(got) != 256 {
		t.Fatalf("want length capped at 256, got %d", len(got))
	}
}
