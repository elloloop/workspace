package middleware

import (
	"strings"
	"testing"
)

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
