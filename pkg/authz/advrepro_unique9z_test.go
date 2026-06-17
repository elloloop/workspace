package authz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type idxReader9z struct {
	idx map[string][]Subject
	n   int
}

func newIdx9z() *idxReader9z { return &idxReader9z{idx: map[string][]Subject{}} }

func (r *idxReader9z) key(ns, obj, rel string) string { return ns + "\x1f" + obj + "\x1f" + rel }

func (r *idxReader9z) add(ns, obj, rel string, s Subject) {
	k := r.key(ns, obj, rel)
	r.idx[k] = append(r.idx[k], s)
}

func (r *idxReader9z) ListSubjects(_ context.Context, _, _, ns, obj, rel string) ([]Subject, error) {
	r.n++
	return r.idx[r.key(ns, obj, rel)], nil
}

func (r *idxReader9z) ListObjectIDs(_ context.Context, _, _, ns string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for k := range r.idx {
		parts := strings.SplitN(k, "\x1f", 3)
		if parts[0] == ns && !seen[parts[1]] {
			seen[parts[1]] = true
			out = append(out, parts[1])
		}
	}
	return out, nil
}

func TestAdv9zSingleCheck(t *testing.T) {
	for _, depth := range []int{10, 20, 50, 90} {
		r := newIdx9z()
		for i := 0; i < depth-1; i++ {
			r.add("resource", fmt.Sprintf("f%d", i), "parent", set("resource", fmt.Sprintf("f%d", i+1), "viewer"))
		}
		e := NewEngine(nil, r)
		_, err := e.Check(context.Background(), "p", "", "resource", "f0", "viewer", "nobody", nil)
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		t.Logf("single Check depth=%d reads=%d", depth, r.n)
	}
}

func TestAdv9zListObjects(t *testing.T) {
	const nCandidates = 100
	const depth = 50
	r := newIdx9z()
	for c := 0; c < nCandidates; c++ {
		for i := 0; i < depth-1; i++ {
			r.add("resource", fmt.Sprintf("c%d_%d", c, i), "parent", set("resource", fmt.Sprintf("c%d_%d", c, i+1), "viewer"))
		}
	}
	e := NewEngine(nil, r)
	ids, _ := r.ListObjectIDs(context.Background(), "p", "", "resource")
	start := time.Now()
	out, err := e.ListObjects(context.Background(), "p", "", "resource", "viewer", "nobody", 0)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ListObjects error: %v", err)
	}
	t.Logf("ListObjects candidates=%d reads=%d elapsed=%s granted=%d", len(ids), r.n, elapsed, len(out))
}

// Stress: MaxListObjects=1000 candidates, depth up to maxDepth boundary, to bound worst case.
func TestAdv9zWorstCase(t *testing.T) {
	const nCandidates = 1000
	const depth = 95
	r := newIdx9z()
	for c := 0; c < nCandidates; c++ {
		for i := 0; i < depth-1; i++ {
			r.add("resource", fmt.Sprintf("c%d_%d", c, i), "parent", set("resource", fmt.Sprintf("c%d_%d", c, i+1), "viewer"))
		}
	}
	e := NewEngine(nil, r)
	ids, _ := r.ListObjectIDs(context.Background(), "p", "", "resource")
	start := time.Now()
	out, err := e.ListObjects(context.Background(), "p", "", "resource", "viewer", "nobody", 0)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Logf("WORST candidates=%d reads=%d elapsed=%s granted=%d", len(ids), r.n, elapsed, len(out))
}

// TestAdv9zCapInteraction: with the production cap (1000), how many reads can a
// single ACCEPTED ListObjects request drive? The cap bounds CANDIDATES (objects
// with any stored tuple), and chain-internal nodes ARE candidates. So to stay
// under the cap while maximizing depth, total objects (nCand * depth) <= 1000.
func TestAdv9zCapInteraction(t *testing.T) {
	const cap = 1000
	// Maximize reads under the cap: total objects <= 1000.
	// Try a few shapes: (nCand, depth) with nCand*depth ~ 1000.
	shapes := [][2]int{{1000, 1}, {100, 10}, {20, 50}, {11, 90}, {1, 95}}
	for _, sh := range shapes {
		nCand, depth := sh[0], sh[1]
		r := newIdx9z()
		for c := 0; c < nCand; c++ {
			for i := 0; i < depth-1; i++ {
				r.add("resource", fmt.Sprintf("c%d_%d", c, i), "parent", set("resource", fmt.Sprintf("c%d_%d", c, i+1), "viewer"))
			}
			// ensure single-node chains still produce a candidate object
			if depth == 1 {
				r.add("resource", fmt.Sprintf("c%d_0", c), "owner", user("someoneelse"))
			}
		}
		ids, _ := r.ListObjectIDs(context.Background(), "p", "", "resource")
		e := NewEngine(nil, r)
		start := time.Now()
		_, err := e.ListObjects(context.Background(), "p", "", "resource", "viewer", "nobody", cap)
		el := time.Since(start)
		t.Logf("shape nCand=%d depth=%d candidates=%d cap=%d -> reads=%d elapsed=%s err=%v",
			nCand, depth, len(ids), cap, r.n, el, err)
	}
}
