package connect

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsBurstThenBlocksAndRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rl := newRateLimiter(3, func() time.Time { return now }) // 3/min, burst 3
	const key = "1.2.3.4"

	for i := 0; i < 3; i++ {
		if !rl.allow(key) {
			t.Fatalf("burst call %d should be allowed", i)
		}
	}
	if rl.allow(key) {
		t.Fatal("4th call should be blocked (bucket empty, no refill yet)")
	}

	// 3/min = 0.05 tok/s; +20s refills exactly one token.
	now = now.Add(20 * time.Second)
	if !rl.allow(key) {
		t.Fatal("one token should have refilled after 20s")
	}
	if rl.allow(key) {
		t.Fatal("only one token refilled; the next call must block")
	}

	// A distinct caller has its own full bucket.
	if !rl.allow("9.9.9.9") {
		t.Fatal("a distinct key should start with a full burst")
	}
}

func TestRateLimiterDisabledAllowsEverything(t *testing.T) {
	rl := newRateLimiter(0, nil) // non-positive => disabled (nil)
	if rl != nil {
		t.Fatalf("non-positive perMinute should yield a nil (disabled) limiter, got %#v", rl)
	}
	for i := 0; i < 1000; i++ {
		if !rl.allow("x") { // nil-receiver allow must return true
			t.Fatal("a disabled (nil) limiter must allow every request")
		}
	}
}
