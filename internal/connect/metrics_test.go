package connect

import (
	"context"
	"strconv"
	"testing"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
)

// runWithBackstops drives fn through the real backstopInterceptor so a test that
// calls a handler method directly still gets the central backstop install +
// once-per-request recording that production wiring provides via
// connect.WithInterceptors. The inner UnaryFunc ignores its request/response and
// just runs fn on the (backstop-carrying) context.
func runWithBackstops(ctx context.Context, h *Handler, fn func(context.Context) error) error {
	interceptor := backstopInterceptor(h.metrics)
	wrapped := interceptor(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, fn(ctx)
	})
	_, err := wrapped(ctx, connect.NewRequest(&workspacev1.CheckRequest{}))
	return err
}

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

// TestRegionRefusedMetric: a request to a project pinned to a different region
// than this instance serves is refused AND increments authz_region_refused_total.
func TestRegionRefusedMetric(t *testing.T) {
	svc := service.New(memory.New(), nil, nil, service.WithDataRegion("us-east-1"))
	ctx := context.Background()
	if _, err := svc.CreateProject(ctx, "eu", "EU", nil, "eu-west-1"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	h := NewHandler(svc, "default", "", "", 100, 0, 0)
	reg := prometheus.NewRegistry()
	h.metrics = newMetrics(reg)

	_, err := h.Check(ctx, connect.NewRequest(&workspacev1.CheckRequest{
		ProjectId: "eu", Namespace: "doc", ObjectId: "d1", Relation: "viewer", SubjectUserId: "u1",
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("mis-routed Check = %v, want FailedPrecondition", err)
	}
	if got := counterValue(t, reg, "authz_region_refused_total", map[string]string{}); got != 1 {
		t.Fatalf("region refused counter = %v, want 1", got)
	}
}

// TestBackstopMetric: a budget-exhausting cyclic resource graph increments
// authz_eval_backstop_total{reason="budget"} (and a generous-budget cyclic Check
// records reason="cycle"/"depth"), giving on-call an alertable signal.
func TestBackstopMetric(t *testing.T) {
	ctx := context.Background()

	// (1) Budget-exhausting graph: a long resource parent chain that loops, with
	// a deliberately tiny read budget → ResourceExhausted + reason="budget".
	svc := service.New(memory.New(), nil, nil, service.WithMaxCheckReads(10))
	h := NewHandler(svc, "default", "", "", 100, 0, 0)
	reg := prometheus.NewRegistry()
	h.metrics = newMetrics(reg)

	const n = 50
	updates := make([]*workspacev1.TupleUpdate, 0, n)
	for i := 1; i <= n; i++ {
		next := i + 1
		if i == n {
			next = 1 // close the loop
		}
		updates = append(updates, &workspacev1.TupleUpdate{
			Op: workspacev1.TupleUpdate_OP_INSERT,
			Tuple: &workspacev1.RelationTuple{
				Namespace: "resource", ObjectId: intName(i), Relation: "parent",
				Subject: &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
					Namespace: "resource", ObjectId: intName(next), Relation: "viewer",
				}}},
			},
		})
	}
	if _, err := h.WriteRelationTuples(ctx, connect.NewRequest(&workspacev1.WriteRelationTuplesRequest{Updates: updates})); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := runWithBackstops(ctx, h, func(ctx context.Context) error {
		_, e := h.Check(ctx, connect.NewRequest(&workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "o1", Relation: "viewer", SubjectUserId: "nobody",
		}))
		return e
	})
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("budget-exhausting Check = %v, want ResourceExhausted", err)
	}
	if got := counterValue(t, reg, "authz_eval_backstop_total", map[string]string{"reason": "budget"}); got != 1 {
		t.Fatalf("budget backstop counter = %v, want 1", got)
	}

	// (2) Generous budget over the same cyclic graph: graceful deny (no error)
	// but the depth/cycle backstop is still counted.
	svc2 := service.New(memory.New(), nil, nil)
	h2 := NewHandler(svc2, "default", "", "", 100, 0, 0)
	reg2 := prometheus.NewRegistry()
	h2.metrics = newMetrics(reg2)
	if _, err := h2.WriteRelationTuples(ctx, connect.NewRequest(&workspacev1.WriteRelationTuplesRequest{Updates: updates})); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if err := runWithBackstops(ctx, h2, func(ctx context.Context) error {
		_, e := h2.Check(ctx, connect.NewRequest(&workspacev1.CheckRequest{
			Namespace: "resource", ObjectId: "o1", Relation: "viewer", SubjectUserId: "nobody",
		}))
		return e
	}); err != nil {
		t.Fatalf("generous-budget Check should not error, got %v", err)
	}
	depth := counterValue(t, reg2, "authz_eval_backstop_total", map[string]string{"reason": "depth"})
	cycle := counterValue(t, reg2, "authz_eval_backstop_total", map[string]string{"reason": "cycle"})
	if depth+cycle == 0 {
		t.Fatalf("expected a depth or cycle backstop counted, got depth=%v cycle=%v", depth, cycle)
	}
}

func intName(i int) string { return "o" + strconv.Itoa(i) }

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
