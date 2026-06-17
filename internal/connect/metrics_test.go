package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

func TestDecisionMetrics(t *testing.T) {
	h := NewHandler(service.New(memory.New(), nil, nil), "default", "", "", 100, 0, 0)
	reg := prometheus.NewRegistry()
	h.metrics = newMetrics(reg) // isolate from the global registry
	ctx := context.Background()

	if _, err := h.WriteRelationTuples(ctx, connect.NewRequest(&workspacev1.WriteRelationTuplesRequest{
		Updates: []*workspacev1.TupleUpdate{{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "workspace", ObjectId: "w1", Relation: "owner",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: "alice"}},
			},
		}},
	})); err != nil {
		t.Fatalf("write: %v", err)
	}

	check := func(user string) {
		if _, err := h.Check(ctx, connect.NewRequest(&workspacev1.CheckRequest{
			Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: user,
		})); err != nil {
			t.Fatalf("check %s: %v", user, err)
		}
	}
	check("alice") // allow
	check("bob")   // deny

	allowL := map[string]string{"namespace": "workspace", "relation": "owner", "allowed": "true"}
	denyL := map[string]string{"namespace": "workspace", "relation": "owner", "allowed": "false"}
	if got := counterValue(t, reg, "authz_check_decisions_total", allowL); got != 1 {
		t.Fatalf("allow decisions = %v, want 1", got)
	}
	if got := counterValue(t, reg, "authz_check_decisions_total", denyL); got != 1 {
		t.Fatalf("deny decisions = %v, want 1", got)
	}

	// BatchCheck: one valid (allow) + one malformed (per-item error).
	if _, err := h.BatchCheck(ctx, connect.NewRequest(&workspacev1.BatchCheckRequest{
		Items: []*workspacev1.BatchCheckItem{
			{Namespace: "workspace", ObjectId: "w1", Relation: "owner", SubjectUserId: "alice"},
			{Namespace: "workspace", ObjectId: "w1", Relation: "", SubjectUserId: "alice"},
		},
	})); err != nil {
		t.Fatalf("batchcheck: %v", err)
	}

	if got := counterValue(t, reg, "authz_check_decisions_total", allowL); got != 2 {
		t.Fatalf("allow decisions after batch = %v, want 2", got)
	}
	if got := counterValue(t, reg, "authz_decision_errors_total", map[string]string{"rpc": "BatchCheck"}); got != 1 {
		t.Fatalf("batchcheck per-item errors = %v, want 1", got)
	}

	// The items-per-request histogram and the BatchCheck/Check latency
	// histograms were observed.
	if n := histogramSamples(t, reg, "authz_batchcheck_items"); n != 1 {
		t.Fatalf("batchcheck items samples = %d, want 1", n)
	}
	if n := histogramSamples(t, reg, "authz_check_duration_seconds"); n < 3 {
		t.Fatalf("check duration samples = %d, want >=3 (2 Check + 1 BatchCheck)", n)
	}
}

// counterValue gathers reg and returns the value of the counter named `name`
// whose label set exactly equals `labels` (0 if absent).
func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if len(m.GetLabel()) != len(labels) {
				continue
			}
			match := true
			for _, lp := range m.GetLabel() {
				if labels[lp.GetName()] != lp.GetValue() {
					match = false
					break
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func histogramSamples(t *testing.T, reg *prometheus.Registry, name string) uint64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var n uint64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			n += m.GetHistogram().GetSampleCount()
		}
	}
	return n
}
