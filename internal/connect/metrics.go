package connect

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// metrics holds the authorization decision instrumentation exposed at /metrics.
// Label cardinality is kept low on purpose — namespace + relation + outcome, and
// the RPC name — never object_id or subject, which are unbounded. All methods
// are nil-safe so an unwired handler simply records nothing.
type metrics struct {
	decisions     *prometheus.CounterVec   // authz_check_decisions_total{namespace,relation,allowed}
	duration      *prometheus.HistogramVec // authz_check_duration_seconds{rpc}
	errors        *prometheus.CounterVec   // authz_decision_errors_total{rpc}
	batchItems    prometheus.Histogram     // authz_batchcheck_items
	regionRefused prometheus.Counter       // authz_region_refused_total
}

// newMetrics constructs and registers the decision metrics on reg.
func newMetrics(reg prometheus.Registerer) *metrics {
	f := promauto.With(reg)
	return &metrics{
		decisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_check_decisions_total",
			Help: "Authorization Check/CheckSet/BatchCheck decisions by namespace, relation, and outcome.",
		}, []string{"namespace", "relation", "allowed"}),
		duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "authz_check_duration_seconds",
			Help:    "Authorization decision RPC latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"rpc"}),
		errors: f.NewCounterVec(prometheus.CounterOpts{
			Name: "authz_decision_errors_total",
			Help: "Authorization decision RPC errors (validation + internal).",
		}, []string{"rpc"}),
		batchItems: f.NewHistogram(prometheus.HistogramOpts{
			Name:    "authz_batchcheck_items",
			Help:    "Items per BatchCheck request.",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000},
		}),
		regionRefused: f.NewCounter(prometheus.CounterOpts{
			Name: "authz_region_refused_total",
			Help: "Requests refused because the project's pinned data region differs from this instance's region (data-residency fail-closed).",
		}),
	}
}

var (
	defaultMetricsOnce sync.Once
	defaultMetricsInst *metrics
)

// defaultMetrics returns the process-wide metrics registered on the default
// Prometheus registry (the one promhttp.Handler() serves at /metrics),
// constructed exactly once so repeated NewHandler calls never re-register.
func defaultMetrics() *metrics {
	defaultMetricsOnce.Do(func() {
		defaultMetricsInst = newMetrics(prometheus.DefaultRegisterer)
	})
	return defaultMetricsInst
}

func (m *metrics) recordDecision(namespace, relation string, allowed bool) {
	if m == nil {
		return
	}
	m.decisions.WithLabelValues(namespace, relation, strconv.FormatBool(allowed)).Inc()
}

func (m *metrics) observe(rpc string, start time.Time) {
	if m == nil {
		return
	}
	m.duration.WithLabelValues(rpc).Observe(time.Since(start).Seconds())
}

func (m *metrics) recordError(rpc string) {
	if m == nil {
		return
	}
	m.errors.WithLabelValues(rpc).Inc()
}

func (m *metrics) observeBatchItems(n int) {
	if m == nil {
		return
	}
	m.batchItems.Observe(float64(n))
}

// recordRegionRefused counts a data-residency fail-closed refusal (the project's
// pinned region differs from this instance's), giving on-call a direct,
// alertable signal that an instance is mis-routed — distinct from a generic
// decision error or a suspended project.
func (m *metrics) recordRegionRefused() {
	if m == nil {
		return
	}
	m.regionRefused.Inc()
}
