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
	if c.PostgresAutoMigrate {
		t.Fatal("auto-migrate should default false (opt-in)")
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
	t.Setenv("GATEWAY_POSTGRES_AUTO_MIGRATE", "true")
	t.Setenv("GATEWAY_SERVICE_AUTH_TOKENS", "a, b ,, c")
	t.Setenv("GATEWAY_ALLOWED_ORIGINS", "https://app.example.com, https://x.example.com")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ConnectPort != 9191 || c.DefaultProjectID != "acme" || c.PostgresDSN != "postgres://x" {
		t.Fatalf("overrides not applied: %+v", c)
	}
	if !c.PostgresAutoMigrate {
		t.Fatal("auto-migrate should parse true when set")
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
		"bad connect port":     func(c *Config) { c.ConnectPort = 0 },
		"bad metrics port":     func(c *Config) { c.MetricsPort = 70000 },
		"zero body bytes":      func(c *Config) { c.HTTPMaxBodyBytes = 0 },
		"weak admin secret":    func(c *Config) { c.AdminAPISecret = "short" },
		"low tenant rate":      func(c *Config) { c.TenantRateLimitPerMinute = 1 },
		"low tenant rate (59)": func(c *Config) { c.TenantRateLimitPerMinute = minTenantRateLimitPerMinute - 1 },
		"low max check reads":  func(c *Config) { c.MaxCheckReads = 5 },
		"max check reads (99)": func(c *Config) { c.MaxCheckReads = MinMaxCheckReads - 1 },
	} {
		c := base()
		mut(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}

	// Empty admin secret is allowed (disables the admin API); a strong one passes.
	c := base()
	c.AdminAPISecret = ""
	if err := c.Validate(); err != nil {
		t.Errorf("empty admin secret rejected: %v", err)
	}
	c.AdminAPISecret = "this-is-a-sufficiently-long-admin-secret-0123456789"
	if err := c.Validate(); err != nil {
		t.Errorf("strong admin secret rejected: %v", err)
	}

	// 0 (disabled) and a value at/above the floor pass.
	c = base()
	c.TenantRateLimitPerMinute = 0
	if err := c.Validate(); err != nil {
		t.Errorf("disabled tenant rate (0) rejected: %v", err)
	}
	c.TenantRateLimitPerMinute = minTenantRateLimitPerMinute
	if err := c.Validate(); err != nil {
		t.Errorf("tenant rate at the floor rejected: %v", err)
	}

	// 0/negative (use the default) and a healthy value pass; a small positive is
	// rejected above.
	c = base()
	c.MaxCheckReads = 0
	if err := c.Validate(); err != nil {
		t.Errorf("default max check reads (0) rejected: %v", err)
	}
	c.MaxCheckReads = -1
	if err := c.Validate(); err != nil {
		t.Errorf("default max check reads (-1) rejected: %v", err)
	}
	c.MaxCheckReads = DefaultMaxCheckReads
	if err := c.Validate(); err != nil {
		t.Errorf("healthy max check reads rejected: %v", err)
	}
}
