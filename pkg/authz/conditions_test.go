package authz

import (
	"context"
	"testing"
)

func userCond(id, name string, params map[string]any) Subject {
	return Subject{UserID: id, Condition: &Condition{Name: name, Params: params}}
}

// TestEvalConditionFailClosed pins the fail-closed contract of the registry.
func TestEvalConditionFailClosed(t *testing.T) {
	cases := []struct {
		name string
		c    *Condition
		ctx  map[string]any
		want bool
	}{
		{"nil condition is unconditional", nil, nil, true},
		{"empty name is unconditional", &Condition{}, nil, true},
		{"unknown name fails closed", &Condition{Name: "no_such"}, map[string]any{}, false},
		{"consent missing fails closed", &Condition{Name: "consent_granted"}, map[string]any{}, false},
		{"consent false denies", &Condition{Name: "consent_granted"}, map[string]any{"consent": false}, false},
		{"consent true allows", &Condition{Name: "consent_granted"}, map[string]any{"consent": true}, true},
		{"age missing param fails closed", &Condition{Name: "age_at_least"}, map[string]any{"age": 20.0}, false},
		{"age below denies", &Condition{Name: "age_at_least", Params: map[string]any{"min_age": 13.0}}, map[string]any{"age": 9.0}, false},
		{"age at threshold allows", &Condition{Name: "age_at_least", Params: map[string]any{"min_age": 13.0}}, map[string]any{"age": 13.0}, true},
		{"ip in cidr allows", &Condition{Name: "ip_in_cidrs", Params: map[string]any{"cidrs": []any{"10.0.0.0/8"}}}, map[string]any{"ip": "10.1.2.3"}, true},
		{"ip outside cidr denies", &Condition{Name: "ip_in_cidrs", Params: map[string]any{"cidrs": []any{"10.0.0.0/8"}}}, map[string]any{"ip": "192.168.0.1"}, false},
		{"not_after before deadline allows", &Condition{Name: "not_after", Params: map[string]any{"until": "2030-01-01T00:00:00Z"}}, map[string]any{"now": "2026-06-16T00:00:00Z"}, true},
		{"not_after past deadline denies", &Condition{Name: "not_after", Params: map[string]any{"until": "2020-01-01T00:00:00Z"}}, map[string]any{"now": "2026-06-16T00:00:00Z"}, false},
	}
	for _, c := range cases {
		if got := EvalCondition(c.c, c.ctx); got != c.want {
			t.Errorf("%s: EvalCondition = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCheckConsentGated: a course#viewer grant conditioned on parental consent
// denies until the request carries consent, then allows — without re-tupling.
func TestCheckConsentGated(t *testing.T) {
	r := &fakeReader{}
	r.add("course", "c1", "viewer", userCond("kid", "consent_granted", nil))
	e := NewEngine(StaticResolver(DefaultModel()), r)
	ctx := context.Background()

	if ok, _ := e.Check(ctx, "p", "", "course", "c1", "viewer", "kid", nil); ok {
		t.Fatal("no consent context: must deny")
	}
	if ok, _ := e.Check(ctx, "p", "", "course", "c1", "viewer", "kid", map[string]any{"consent": false}); ok {
		t.Fatal("consent=false: must deny")
	}
	if ok, _ := e.Check(ctx, "p", "", "course", "c1", "viewer", "kid", map[string]any{"consent": true}); !ok {
		t.Fatal("consent=true: must allow")
	}
}

// TestCheckAgeBand: an age_at_least condition admits only an in-band child, and
// an unconditional grant on the same namespace ignores context.
func TestCheckAgeBand(t *testing.T) {
	r := &fakeReader{}
	r.add("course", "rated", "viewer", userCond("kid", "age_at_least", map[string]any{"min_age": 13.0}))
	r.add("course", "open", "viewer", user("kid")) // unconditional
	e := NewEngine(StaticResolver(DefaultModel()), r)
	ctx := context.Background()

	if ok, _ := e.Check(ctx, "p", "", "course", "rated", "viewer", "kid", map[string]any{"age": 9.0}); ok {
		t.Fatal("age 9 below band: must deny")
	}
	if ok, _ := e.Check(ctx, "p", "", "course", "rated", "viewer", "kid", map[string]any{"age": 15.0}); !ok {
		t.Fatal("age 15 in band: must allow")
	}
	// Unconditional grant is unaffected by (even absent) context.
	if ok, _ := e.Check(ctx, "p", "", "course", "open", "viewer", "kid", nil); !ok {
		t.Fatal("unconditional grant must allow regardless of context")
	}
}
