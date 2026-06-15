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

	AllowedOrigins   []string
	HTTPMaxBodyBytes int64
}

// Load reads configuration from the environment, applying defaults.
func Load() (*Config, error) {
	c := &Config{
		ConnectPort:         envInt("GATEWAY_CONNECT_PORT", 8080),
		MetricsPort:         envInt("GATEWAY_METRICS_PORT", 9090),
		DefaultProjectID:    envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		PostgresDSN:         envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresAutoMigrate: envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", true),
		ServiceAuthTokens:   envCSV("GATEWAY_SERVICE_AUTH_TOKENS"),
		AllowedOrigins:      envCSV("GATEWAY_ALLOWED_ORIGINS"),
		HTTPMaxBodyBytes:    int64(envInt("GATEWAY_HTTP_MAX_BODY_BYTES", 1<<20)),
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
	return nil
}

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
