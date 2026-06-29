// Package config loads the workspace service configuration from the
// environment. All knobs use the GATEWAY_ prefix, matching the identity
// service so the two deploy with one consistent convention.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/elloloop/workspace/internal/middleware"
)

//go:generate go run ./gen

// DefaultProjectIDFallback is used when no default project is configured.
const DefaultProjectIDFallback = "default"

// Config is the fully-resolved service configuration.
type Config struct {
	// ConnectPort is the Connect/HTTP listener serving JSON, gRPC, and
	// gRPC-Web RPCs.
	ConnectPort int
	// MetricsPort serves the Prometheus /metrics endpoint and the health probes.
	MetricsPort int
	// DefaultProjectID is the project shard used for any request whose
	// project_id is empty.
	DefaultProjectID string
	// DefaultTenantID is the tenant pinned for requests that omit tenant_id
	// (the project's default tenant). Empty is the conventional default.
	DefaultTenantID string

	// DataRegion is the region this instance serves: it refuses to operate on a
	// project pinned to a different data_region (fail closed). Empty (default)
	// is region-agnostic — serves every project, today's behavior.
	DataRegion string

	// PostgresDSN selects the postgres driver when set; empty uses memory.
	PostgresDSN string
	// PostgresAutoMigrate runs the expand migration on boot when true. It
	// defaults to FALSE: migrations are a deliberate operator step (out-of-band
	// `workspace migrate`, an init container, or a migrate Job), so a large
	// existing DB's first deploy can never livelock on a bounded CONCURRENTLY
	// build inside the boot window. Opt in (true) only for small/dev DBs.
	PostgresAutoMigrate bool

	// ServiceAuthTokens are the accepted service credentials presented by
	// calling backends as `Authorization: Bearer <token>`. This is an
	// internal service authenticated service-to-service (not by end-user
	// tokens); the user is passed as data in the request. Empty disables the
	// requirement — trust the network/mesh — and the service logs a warning.
	ServiceAuthTokens []string

	// ServiceCredentials is the OPTIONAL typed mapping (from GATEWAY_SERVICE_
	// CREDENTIALS, a JSON list of {token, name, project}) of a service credential
	// to a named calling-service identity with an optional project pin. It is
	// additive: ServiceAuthTokens keep working as anonymous credentials.
	ServiceCredentials []middleware.ServiceCredential

	// AdminAPISecret gates the AdminService (project configuration), presented
	// as the `X-Admin-Secret` header. Empty disables the admin RPCs entirely.
	AdminAPISecret string

	// AllowedOrigins is the CORS allow-list of browser origins permitted to
	// call the API. Empty allows none.
	AllowedOrigins []string
	// HTTPMaxBodyBytes is the maximum accepted request body, in bytes. Must be
	// positive.
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
	// MaxCheckReads caps the number of store reads (tuple lookups) a single
	// Check/CheckSet/Expand/ListObjects evaluation may perform, bounding the
	// per-request cost a pathological cyclic/branching graph can inflict.
	// Non-positive uses the service default.
	MaxCheckReads int
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

// DefaultMaxCheckReads bounds the store reads one Check/CheckSet/Expand/
// ListObjects evaluation may perform when not overridden. Generous on purpose:
// legitimate deep folder/group hierarchies read far fewer tuples than this, so
// the budget only trips on a pathological cyclic/branching graph.
const DefaultMaxCheckReads = 5000

// Load reads configuration from the environment, applying defaults.
func Load() (*Config, error) {
	c := &Config{
		ConnectPort:              envInt("GATEWAY_CONNECT_PORT", 8080),
		MetricsPort:              envInt("GATEWAY_METRICS_PORT", 9090),
		DefaultProjectID:         envStr("GATEWAY_DEFAULT_PROJECT_ID", DefaultProjectIDFallback),
		DefaultTenantID:          envStr("GATEWAY_DEFAULT_TENANT_ID", ""),
		DataRegion:               envStr("GATEWAY_DATA_REGION", ""),
		PostgresDSN:              envStr("GATEWAY_POSTGRES_DSN", ""),
		PostgresAutoMigrate:      envBool("GATEWAY_POSTGRES_AUTO_MIGRATE", false),
		ServiceAuthTokens:        envCSV("GATEWAY_SERVICE_AUTH_TOKENS"),
		AdminAPISecret:           envStr("GATEWAY_ADMIN_API_SECRET", ""),
		AllowedOrigins:           envCSV("GATEWAY_ALLOWED_ORIGINS"),
		HTTPMaxBodyBytes:         int64(envInt("GATEWAY_HTTP_MAX_BODY_BYTES", 1<<20)),
		MaxListObjects:           envInt("GATEWAY_MAX_LIST_OBJECTS", DefaultMaxListObjects),
		MaxExpandNodes:           envInt("GATEWAY_MAX_EXPAND_NODES", DefaultMaxExpandNodes),
		MaxBatchCheckItems:       envInt("GATEWAY_MAX_BATCH_CHECK_ITEMS", DefaultMaxBatchCheckItems),
		MaxCheckReads:            envInt("GATEWAY_MAX_CHECK_READS", DefaultMaxCheckReads),
		AdminRateLimitPerMinute:  envInt("GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE", DefaultAdminRateLimitPerMinute),
		TenantRateLimitPerMinute: envInt("GATEWAY_TENANT_RATE_LIMIT_PER_MINUTE", 0),
		DecisionLog:              envBool("GATEWAY_DECISION_LOG", false),
		AuditLog:                 envBool("GATEWAY_AUDIT_LOG", false),
	}
	creds, err := parseServiceCredentials(os.Getenv("GATEWAY_SERVICE_CREDENTIALS"))
	if err != nil {
		return nil, fmt.Errorf("GATEWAY_SERVICE_CREDENTIALS: %w", err)
	}
	c.ServiceCredentials = creds
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// parseServiceCredentials decodes the optional GATEWAY_SERVICE_CREDENTIALS JSON
// (a list of {token, name, project}); empty/unset yields no credentials. Each
// entry must carry a non-empty token and name.
func parseServiceCredentials(raw string) ([]middleware.ServiceCredential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var creds []middleware.ServiceCredential
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&creds); err != nil {
		// Do NOT wrap the decoder error verbatim — the raw JSON (and thus token
		// bytes) can appear in it. Report only that the value is malformed.
		return nil, errors.New("GATEWAY_SERVICE_CREDENTIALS is not valid JSON")
	}
	for i, c := range creds {
		// Identify a bad entry by INDEX (and at most its non-secret name), never
		// by token value, so a credential secret can never reach a log.
		if strings.TrimSpace(c.Token) == "" {
			return nil, fmt.Errorf("credential %d: token is required", i)
		}
		if len(c.Token) < minServiceCredentialLen {
			return nil, fmt.Errorf("credential %d (%q): token must be a high-entropy value of at least %d characters", i, c.Name, minServiceCredentialLen)
		}
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("credential %d: name is required", i)
		}
	}
	return creds, nil
}

// minServiceCredentialLen floors a mapped service credential's token: it both
// authenticates AND authorizes (via its project pin), so it must not be
// brute-forceable. Mirrors minAdminSecretLen.
const minServiceCredentialLen = minAdminSecretLen

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
	// A small positive per-minute cap would silently throttle the authz data
	// plane to a near-zero rate; require a sane floor when enabled (0 disables).
	if c.TenantRateLimitPerMinute > 0 && c.TenantRateLimitPerMinute < minTenantRateLimitPerMinute {
		return fmt.Errorf("GATEWAY_TENANT_RATE_LIMIT_PER_MINUTE, when enabled, must be >= %d (use 0 to disable)", minTenantRateLimitPerMinute)
	}
	// A small-positive MaxCheckReads would silently fail authz CLOSED fleet-wide
	// (every non-trivial Check trips the budget → ResourceExhausted). Require a
	// sane floor when set; 0/negative keeps the generous service default.
	if c.MaxCheckReads > 0 && c.MaxCheckReads < MinMaxCheckReads {
		return fmt.Errorf("GATEWAY_MAX_CHECK_READS, when set, must be >= %d (use 0/negative for the default)", MinMaxCheckReads)
	}
	// The instance region is compared char-for-char against a project's pinned
	// data_region (same lowercase [a-z0-9_-], <=64 charset). Reject a malformed
	// value at startup, otherwise a case/charset typo would silently fail closed
	// for every project it should match.
	if err := validateDataRegion(c.DataRegion); err != nil {
		return err
	}
	return nil
}

// maxDataRegionLen bounds the instance data-region identifier; it MUST match the
// service's project-side validateRegion rule so the two compare cleanly.
const maxDataRegionLen = 64

// validateDataRegion enforces the same charset as a project's data_region: empty
// (region-agnostic) or lowercase [a-z0-9_-], at most maxDataRegionLen chars.
func validateDataRegion(region string) error {
	if region == "" {
		return nil
	}
	if len(region) > maxDataRegionLen {
		return fmt.Errorf("GATEWAY_DATA_REGION must be at most %d characters", maxDataRegionLen)
	}
	for _, ch := range region {
		ok := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_'
		if !ok {
			return errors.New("GATEWAY_DATA_REGION must be lowercase [a-z0-9_-]")
		}
	}
	return nil
}

// minAdminSecretLen is the minimum length for a configured admin secret.
const minAdminSecretLen = 32

// minTenantRateLimitPerMinute is the floor for an enabled per-tenant rate limit,
// above any plausible single-tenant burst, so a misconfigured small value cannot
// throttle the authz data plane to a near-zero cap.
const minTenantRateLimitPerMinute = 60

// MinMaxCheckReads floors a configured per-request read budget — both the global
// GATEWAY_MAX_CHECK_READS and a per-project override (service.CreateProject /
// UpdateProject reuse this same floor). Well below DefaultMaxCheckReads but above
// any real single-evaluation read count, so a small-positive typo (e.g. 5) is
// rejected rather than silently failing authz closed; 0/negative selects the
// default.
const MinMaxCheckReads = 100

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
