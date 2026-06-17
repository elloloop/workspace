// Package config loads the workspace service configuration from the
// environment. All knobs use the GATEWAY_ prefix, matching the identity
// service so the two deploy with one consistent convention.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultProjectIDFallback is used when no default project is configured.
const DefaultProjectIDFallback = "default"

// Config is the fully-resolved service configuration.
type Config struct {
	ConnectPort      int
	MetricsPort      int
	DefaultProjectID string
	// DefaultTenantID is the tenant pinned for requests that omit tenant_id
	// (the project's default tenant). Empty is the conventional default.
	DefaultTenantID string

	// PostgresDSN selects the postgres driver when set; empty uses memory.
	PostgresDSN string
	// PostgresAutoMigrate runs pending migrations on boot when true.
	PostgresAutoMigrate bool

	// ServiceAuthTokens are the accepted service credentials presented by
	// calling backends as `Authorization: Bearer <token>`. This is an
	// internal service authenticated service-to-service (not by end-user
	// tokens); the user is passed as data in the request. Empty disables the
	// requirement — trust the network/mesh — and the service logs a warning.
	ServiceAuthTokens []string

	// AdminAPISecret gates the AdminService (project configuration), presented
	// as the `X-Admin-Secret` header. Empty disables the admin RPCs entirely.
	AdminAPISecret string

	AllowedOrigins   []string
	HTTPMaxBodyBytes int64

	// MaxListObjects caps the candidate set a single ListObjects call scans,
	// bounding its full-scan + per-object Check cost.
	MaxListObjects int
	// MaxExpandNodes caps the size of an Expand result tree, bounding the
	// response a single cheap request can amplify into.
	MaxExpandNodes int
	// MaxBatchCheckItems caps the number of items in a single BatchCheck
	// request, bounding per-request cost.
	MaxBatchCheckItems int
	// AdminRateLimitPerMinute throttles the admin API per caller (online
	// brute-force protection); non-positive disables the limiter.
	AdminRateLimitPerMinute int
	// TenantRateLimitPerMinute throttles authz data-plane RPCs per
	// (project, tenant); non-positive (the default) disables the limiter.
	TenantRateLimitPerMinute int
	// DecisionLog enables an async, append-only audit log of every Check/
	// CheckSet decision (to the structured logger). Default false.
	DecisionLog bool
	// AuditLog enables an async, append-only audit log of every relation-tuple
	// change and admin mutation (to the structured logger). Default false.
	AuditLog bool
}

// DefaultMaxListObjects bounds a ListObjects request when not overridden.
const DefaultMaxListObjects = 1000

// DefaultAdminRateLimitPerMinute throttles the admin API per caller when not
// overridden.
const DefaultAdminRateLimitPerMinute = 30

// DefaultMaxExpandNodes bounds an Expand result tree when not overridden.
const DefaultMaxExpandNodes = 10000

// DefaultMaxBatchCheckItems bounds a BatchCheck request when not overridden.
const DefaultMaxBatchCheckItems = 1000

// Load reads configuration from the environment, applying defaults.
func Load() (*Config, error) {
	c := &Config{
		ConnectPort:              envInt("GATEWAY_CONNECT_PORT", 8080),
		MetricsPort:              envInt("GATEWAY_METRICS_PORT", 9090),
		DefaultProjectID:         envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		DefaultTenantID:          envStr("GATEWAY_DEFAULT_TENANT_ID", ""),
		PostgresDSN:              envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresAutoMigrate:      envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", true),
		ServiceAuthTokens:        envCSV("GATEWAY_SERVICE_AUTH_TOKENS"),
		AdminAPISecret:           envStr("GATEWAY_ADMIN_API_SECRET", ""),
		AllowedOrigins:           envCSV("GATEWAY_ALLOWED_ORIGINS"),
		HTTPMaxBodyBytes:         int64(envInt("GATEWAY_HTTP_MAX_BODY_BYTES", 1<<20)),
		MaxListObjects:           envInt("GATEWAY_MAX_LIST_OBJECTS", DefaultMaxListObjects),
		MaxExpandNodes:           envInt("GATEWAY_MAX_EXPAND_NODES", DefaultMaxExpandNodes),
		MaxBatchCheckItems:       envInt("GATEWAY_MAX_BATCH_CHECK_ITEMS", DefaultMaxBatchCheckItems),
		AdminRateLimitPerMinute:  envInt("GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE", DefaultAdminRateLimitPerMinute),
		TenantRateLimitPerMinute: envInt("GATEWAY_TENANT_RATE_LIMIT_PER_MINUTE", 0),
		DecisionLog:              envBool("GATEWAY_DECISION_LOG", false),
		AuditLog:                 envBool("GATEWAY_AUDIT_LOG", false),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks invariants that defaults cannot express.
func (c *Config) Validate() error {
	if c.ConnectPort <= 0 || c.ConnectPort > 65535 {
		return fmt.Errorf("GATEWAY_CONNECT_PORT out of range: %d", c.ConnectPort)
	}
	if c.MetricsPort <= 0 || c.MetricsPort > 65535 {
		return fmt.Errorf("GATEWAY_METRICS_PORT out of range: %d", c.MetricsPort)
	}
	if c.HTTPMaxBodyBytes <= 0 {
		return errors.New("GATEWAY_HTTP_MAX_BODY_BYTES must be positive")
	}
	// The admin secret guards the project-model-takeover surface; reject a weak
	// one outright rather than serving a brute-forceable credential. Empty is
	// allowed (it disables the admin API entirely).
	if c.AdminAPISecret != "" && len(c.AdminAPISecret) < minAdminSecretLen {
		return fmt.Errorf("GATEWAY_ADMIN_API_SECRET must be a high-entropy value of at least %d characters", minAdminSecretLen)
	}
	return nil
}

// minAdminSecretLen is the minimum length for a configured admin secret.
const minAdminSecretLen = 32

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return def
}

func envCSV(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
