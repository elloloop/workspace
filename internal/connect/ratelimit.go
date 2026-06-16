package connect

import (
	"net"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
)

// rateLimiter is a goroutine-safe, per-key token-bucket limiter. Each key gets
// a bucket of `capacity` tokens that refills at `refill` tokens/second; one
// token is consumed per allowed request. It is used to throttle online
// brute-force against the admin secret. A nil *rateLimiter allows everything
// (the limiter is disabled).
type rateLimiter struct {
	capacity float64
	refill   float64 // tokens per second
	now      func() time.Time

	mu        sync.Mutex
	buckets   map[string]*tokenBucket
	lastPrune time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter allowing up to perMinute requests per key
// (burst = perMinute). A non-positive perMinute returns nil (disabled). now is
// injectable for deterministic tests; nil uses time.Now.
func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		capacity: float64(perMinute),
		refill:   float64(perMinute) / 60.0,
		now:      now,
		buckets:  map[string]*tokenBucket{},
	}
}

// allow consumes a token for key, returning false when the bucket is empty. A
// nil limiter always allows.
func (r *rateLimiter) allow(key string) bool {
	if r == nil {
		return true
	}
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)

	b := r.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: r.capacity, last: now}
		r.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(r.capacity, b.tokens+elapsed*r.refill)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// pruneLocked drops buckets idle long enough to have fully refilled (which are
// indistinguishable from a fresh bucket), bounding memory. The caller holds mu.
func (r *rateLimiter) pruneLocked(now time.Time) {
	if now.Sub(r.lastPrune) < time.Minute {
		return
	}
	r.lastPrune = now
	for k, b := range r.buckets {
		if now.Sub(b.last) > 2*time.Minute {
			delete(r.buckets, k)
		}
	}
}

// callerKey identifies the request source for rate limiting: the first
// X-Forwarded-For hop when present (the limiter sits behind a trusted proxy/
// mesh), else the peer IP without its port.
func callerKey(req connect.AnyRequest) string {
	if xff := req.Header().Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	addr := req.Peer().Addr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
