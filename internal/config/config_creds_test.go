package config

import (
	"strings"
	"testing"
)

func TestParseServiceCredentials(t *testing.T) {
	t.Run("empty yields none", func(t *testing.T) {
		got, err := parseServiceCredentials("   ")
		if err != nil || got != nil {
			t.Fatalf("empty = (%v, %v), want (nil, nil)", got, err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		got, err := parseServiceCredentials(`[{"token":"t1","name":"slack","project":"p1"},{"token":"t2","name":"linear"}]`) //nolint:gosec // test-only credential JSON
		if err != nil {
			t.Fatalf("valid: %v", err)
		}
		if len(got) != 2 || got[0].Name != "slack" || got[0].ProjectID != "p1" || got[1].Name != "linear" || got[1].ProjectID != "" {
			t.Fatalf("valid parse = %+v", got)
		}
	})

	for name, raw := range map[string]string{ //nolint:gosec // test-only credential JSON fixtures
		"bad json":      `{not json`,
		"unknown field": `[{"token":"t","name":"n","extra":1}]`,
		"missing token": `[{"name":"slack"}]`,
		"missing name":  `[{"token":"t1"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseServiceCredentials(raw); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

func TestLoadServiceCredentials(t *testing.T) {
	t.Setenv("GATEWAY_SERVICE_CREDENTIALS", `[{"token":"tok","name":"slack","project":"slack-proj"}]`)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.ServiceCredentials) != 1 || c.ServiceCredentials[0].Name != "slack" || c.ServiceCredentials[0].ProjectID != "slack-proj" {
		t.Fatalf("ServiceCredentials = %+v", c.ServiceCredentials)
	}

	t.Setenv("GATEWAY_SERVICE_CREDENTIALS", `[{"name":"missing-token"}]`)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GATEWAY_SERVICE_CREDENTIALS") {
		t.Fatalf("bad credentials should fail Load with a GATEWAY_SERVICE_CREDENTIALS error, got %v", err)
	}
}
