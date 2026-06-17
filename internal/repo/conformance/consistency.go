package conformance

import (
	"testing"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// testConsistencyToken pins the monotonic per-shard write sequence that backs
// read-after-write: it starts at 0, strictly increases on each WriteTuples, and
// is isolated per (project, tenant) — identically across drivers.
func testConsistencyToken(t *testing.T, r service.Repository) {
	t.Helper()
	const p, t1, t2 = "proj", "tenantA", "tenantB"

	seq := func(tenant string) int64 {
		v, err := r.ConsistencyToken(ctx(), p, tenant)
		if err != nil {
			t.Fatalf("ConsistencyToken(%s): %v", tenant, err)
		}
		return v
	}
	write := func(tenant, obj string) int64 {
		if err := r.WriteTuples(ctx(), p, tenant, []authz.Tuple{userTuple("doc", obj, "viewer", "u1")}, nil); err != nil {
			t.Fatalf("WriteTuples: %v", err)
		}
		return seq(tenant)
	}

	// A never-written shard is at 0.
	if got := seq(t1); got != 0 {
		t.Fatalf("fresh shard seq = %d, want 0", got)
	}

	// Each write to t1 strictly advances its sequence.
	first := write(t1, "a")
	if first <= 0 {
		t.Fatalf("seq after first write = %d, want > 0", first)
	}
	if second := write(t1, "b"); second <= first {
		t.Fatalf("seq must strictly increase: first=%d second=%d", first, second)
	}
	t1now := seq(t1)

	// t2 has its own independent sequence, unaffected by t1's writes.
	if got := seq(t2); got != 0 {
		t.Fatalf("sibling tenant seq = %d, want 0 (isolated)", got)
	}
	if t2first := write(t2, "a"); t2first != 1 {
		t.Fatalf("first write to t2 seq = %d, want 1 (independent counter)", t2first)
	}
	// t1 is unmoved by t2's write.
	if got := seq(t1); got != t1now {
		t.Fatalf("t1 seq moved due to a t2 write: %d != %d", got, t1now)
	}
}
