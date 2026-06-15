package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Unset every knob so the defaults apply (set-empty is not the same as
	// unset for the string fallbacks). t.Setenv registers cleanup so the
	// values are restored after the test.
	for _, k := range []string{
		"GATEWAY_CONNECT_PORT", "GATEWAY_METRICS_PORT", "GATEWAY_DEFAULT_PROJECT_ID",
		"GATEWAY_POSTGRES_DSN", "GATEWAY_SERVICE_AUTH_TOKENS", "GATEWAY_ALLOWED_ORIGINS",
		"GATEWAY_HTTP_MAX_BODY_BYTES", "GATEWAY_POSTGRES_AUTO_MIGRATE",
	} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ConnectPort != 8080 || c.MetricsPort != 9090 {
		t.Fatalf("ports = %d/%d, want 8080/9090", c.ConnectPort, c.MetricsPort)
	}
	if c.DefaultProjectID != DefaultProjectIDFallback {
		t.Fatalf("default project = %q, want %q", c.DefaultProjectID, DefaultProjectIDFallback)
	}
	if !c.PostgresAutoMigrate {
		t.Fatal("auto-migrate should default true")
	}
	if c.HTTPMaxBodyBytes != 1<<20 {
		t.Fatalf("max body = %d, want %d", c.HTTPMaxBodyBytes, 1<<20)
	}
	if len(c.ServiceAuthTokens) != 0 {
		t.Fatalf("service tokens should default empty, got %v", c.ServiceAuthTokens)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("GATEWAY_CONNECT_PORT", "9191")
	t.Setenv("GATEWAY_DEFAULT_PROJECT_ID", "acme")
	t.Setenv("GATEWAY_POSTGRES_DSN", "postgres://x")
	t.Setenv("GATEWAY_POSTGRES_AUTO_MIGRATE", "false")
	t.Setenv("GATEWAY_SERVICE_AUTH_TOKENS", "a, b ,, c")
	t.Setenv("GATEWAY_ALLOWED_ORIGINS", "https://app.example.com, https://x.example.com")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ConnectPort != 9191 || c.DefaultProjectID != "acme" || c.PostgresDSN != "postgres://x" {
		t.Fatalf("overrides not applied: %+v", c)
	}
	if c.PostgresAutoMigrate {
		t.Fatal("auto-migrate should be false")
	}
	if len(c.ServiceAuthTokens) != 3 { // empty entries trimmed
		t.Fatalf("service tokens = %v, want 3 non-empty", c.ServiceAuthTokens)
	}
	if len(c.AllowedOrigins) != 2 {
		t.Fatalf("origins = %v, want 2", c.AllowedOrigins)
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		return &Config{ConnectPort: 8080, MetricsPort: 9090, HTTPMaxBodyBytes: 1024}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"bad connect port": func(c *Config) { c.ConnectPort = 0 },
		"bad metrics port": func(c *Config) { c.MetricsPort = 70000 },
		"zero body bytes":  func(c *Config) { c.HTTPMaxBodyBytes = 0 },
	} {
		c := base()
		mut(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}
