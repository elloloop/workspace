package authz

import (
	"fmt"
	"net"
	"time"
)

// Condition is an optional, fail-closed predicate attached to a stored grant
// (relation tuple). When present, the grant applies only if the named, pinned
// condition function evaluates true against the static Params (bound at write
// time) and the request-time context passed to Check. An unknown name, an
// evaluation error, or a missing/ill-typed input all DENY (fail closed).
// Condition is grant metadata, not part of tuple identity — re-writing a tuple
// replaces its condition; deletes still match by identity.
//
// This is the single attribute-aware mechanism behind COPPA parental-consent
// gating, kids age-band gating, scoped integration delegation, and time/IP
// bound shares. Per-project condition DEFINITIONS (beyond this pinned built-in
// set) are a tracked follow-up, as is a richer expression evaluator (e.g. CEL).
type Condition struct {
	Name   string
	Params map[string]any
}

// ConditionFunc evaluates a condition. params are the static parameters stored
// with the grant; ctx is the request-time context. A non-nil error (missing or
// ill-typed input) is treated as DENY by EvalCondition.
type ConditionFunc func(params, ctx map[string]any) (bool, error)

// conditionRegistry is the pinned, read-only set of built-in conditions.
var conditionRegistry = map[string]ConditionFunc{
	"consent_granted": condConsentGranted,
	"age_at_least":    condAgeAtLeast,
	"ip_in_cidrs":     condIPInCIDRs,
	"not_after":       condNotAfter,
}

// KnownCondition reports whether name is a registered built-in condition. The
// write path uses it to reject a grant that references an unknown condition.
func KnownCondition(name string) bool {
	_, ok := conditionRegistry[name]
	return ok
}

// EvalCondition reports whether condition c is satisfied by the request context.
// A nil/empty condition is always satisfied. An unknown name, an evaluation
// error, or a missing/ill-typed input returns false — fail closed. The result
// means "this grant applies"; callers treat false as "this grant does not grant".
func EvalCondition(c *Condition, ctx map[string]any) bool {
	if c == nil || c.Name == "" {
		return true
	}
	fn, ok := conditionRegistry[c.Name]
	if !ok {
		return false // unknown condition: fail closed
	}
	ok, err := fn(c.Params, ctx)
	if err != nil {
		return false // unevaluable / missing input: fail closed
	}
	return ok
}

// ── built-in conditions (pure, side-effect-free) ──────────────────────────

// consent_granted: context["consent"] must be boolean true (e.g. verifiable
// parental consent recorded). No static params.
func condConsentGranted(_, ctx map[string]any) (bool, error) {
	b, err := boolField(ctx, "consent")
	if err != nil {
		return false, err
	}
	return b, nil
}

// age_at_least: context["age"] >= params["min_age"].
func condAgeAtLeast(params, ctx map[string]any) (bool, error) {
	min, err := numField(params, "min_age")
	if err != nil {
		return false, err
	}
	age, err := numField(ctx, "age")
	if err != nil {
		return false, err
	}
	return age >= min, nil
}

// ip_in_cidrs: context["ip"] is within any of params["cidrs"].
func condIPInCIDRs(params, ctx map[string]any) (bool, error) {
	ipStr, err := strField(ctx, "ip")
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("ip_in_cidrs: context %q is not an IP address", "ip")
	}
	cidrs, err := strSliceField(params, "cidrs")
	if err != nil {
		return false, err
	}
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return false, fmt.Errorf("ip_in_cidrs: invalid cidr %q: %w", c, err)
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// not_after: the grant is valid only up to params["until"] (RFC3339), compared
// against context["now"] (RFC3339). The caller supplies "now" so the engine
// stays a pure function of its inputs.
func condNotAfter(params, ctx map[string]any) (bool, error) {
	untilStr, err := strField(params, "until")
	if err != nil {
		return false, err
	}
	until, err := time.Parse(time.RFC3339, untilStr)
	if err != nil {
		return false, fmt.Errorf("not_after: invalid until %q: %w", untilStr, err)
	}
	nowStr, err := strField(ctx, "now")
	if err != nil {
		return false, err
	}
	now, err := time.Parse(time.RFC3339, nowStr)
	if err != nil {
		return false, fmt.Errorf("not_after: invalid now %q: %w", nowStr, err)
	}
	return !now.After(until), nil
}

// ── typed field helpers (JSON/structpb yield float64 numbers and []any) ────

func boolField(m map[string]any, k string) (bool, error) {
	v, ok := m[k]
	if !ok {
		return false, fmt.Errorf("missing %q", k)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%q must be a bool", k)
	}
	return b, nil
}

func numField(m map[string]any, k string) (float64, error) {
	v, ok := m[k]
	if !ok {
		return 0, fmt.Errorf("missing %q", k)
	}
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	default:
		return 0, fmt.Errorf("%q must be a number", k)
	}
}

func strField(m map[string]any, k string) (string, error) {
	v, ok := m[k]
	if !ok {
		return "", fmt.Errorf("missing %q", k)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string", k)
	}
	return s, nil
}

func strSliceField(m map[string]any, k string) ([]string, error) {
	v, ok := m[k]
	if !ok {
		return nil, fmt.Errorf("missing %q", k)
	}
	switch a := v.(type) {
	case []string:
		return a, nil
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%q must be an array of strings", k)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%q must be an array of strings", k)
	}
}
