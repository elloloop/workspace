package conformance

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// seatTuple is the backing relation tuple AssignSeatAndTuple writes.
func seatTup(sku, user string) authz.Tuple {
	return userTuple("seat", sku, service.SeatRelation, user)
}

// testSeats pins the seat/license overlay identically across drivers: limit
// enforcement (fail-closed at the cap), idempotent re-assign, revoke frees a
// seat, usage reporting, the backing tuple moving with the assignment, and —
// critically — that concurrent assigns cannot oversubscribe the cap.
func testSeats(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC()
	assign := func(sku, user string) (bool, error) {
		return r.AssignSeatAndTuple(ctx(), &service.SeatAssignment{
			ProjectID: p, SKU: sku, UserID: user, AssignedAt: now,
		}, seatTup(sku, user))
	}

	// No limit configured → unlimited.
	if u, err := r.GetSeatUsage(ctx(), p, "", "free"); err != nil || u.Limited {
		t.Fatalf("unset limit must be unlimited: %+v %v", u, err)
	}
	for i, user := range []string{"a", "b", "c"} {
		if held, err := assign("free", user); err != nil || held {
			t.Fatalf("unlimited assign %d: held=%v err=%v", i, held, err)
		}
	}

	// Cap "pro" at 2.
	if err := r.SetSeatLimit(ctx(), p, "", "pro", 2); err != nil {
		t.Fatalf("SetSeatLimit: %v", err)
	}
	if held, err := assign("pro", "u1"); err != nil || held {
		t.Fatalf("pro u1: held=%v err=%v", held, err)
	}
	if held, err := assign("pro", "u2"); err != nil || held {
		t.Fatalf("pro u2: held=%v err=%v", held, err)
	}
	// Third over the cap → fail closed, assign nothing.
	if _, err := assign("pro", "u3"); !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("pro u3 over cap: want ErrResourceExhausted, got %v", err)
	}
	// The backing tuple must NOT have been written for the rejected assign.
	if subs, _ := r.ListSubjects(ctx(), p, "", "seat", "pro", service.SeatRelation); len(subs) != 2 {
		t.Fatalf("rejected assign must write no tuple: seat holders = %d, want 2", len(subs))
	}
	// Re-assigning a seated user is idempotent (no extra seat consumed).
	if held, err := assign("pro", "u1"); err != nil || !held {
		t.Fatalf("idempotent re-assign: held=%v err=%v (want held=true)", held, err)
	}
	if u, err := r.GetSeatUsage(ctx(), p, "", "pro"); err != nil || u.Used != 2 || u.Limit != 2 || !u.Limited {
		t.Fatalf("usage = %+v %v; want used=2 limit=2 limited", u, err)
	}

	// Revoke frees a seat → a new user fits.
	if err := r.RevokeSeatAndTuple(ctx(), p, "", "pro", "u2", seatTup("pro", "u2")); err != nil {
		t.Fatalf("RevokeSeat: %v", err)
	}
	if held, err := assign("pro", "u3"); err != nil || held {
		t.Fatalf("assign after revoke: held=%v err=%v", held, err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "seat", "pro", service.SeatRelation); len(subs) != 2 {
		t.Fatalf("seat holders after revoke+assign = %d, want 2", len(subs))
	}
	if seats, _ := r.ListSeats(ctx(), p, "", "pro"); len(seats) != 2 {
		t.Fatalf("ListSeats = %d, want 2", len(seats))
	}

	// Concurrency: with a cap of 3 and 20 distinct concurrent assigns, EXACTLY 3
	// may succeed — no oversubscription.
	if err := r.SetSeatLimit(ctx(), p, "", "race", 3); err != nil {
		t.Fatalf("SetSeatLimit race: %v", err)
	}
	const racers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, exhausted := 0, 0
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			user := fmt.Sprintf("racer-%d", n)
			_, err := r.AssignSeatAndTuple(ctx(), &service.SeatAssignment{
				ProjectID: p, SKU: "race", UserID: user, AssignedAt: now,
			}, seatTup("race", user))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, service.ErrResourceExhausted):
				exhausted++
			default:
				t.Errorf("racer %d unexpected err: %v", n, err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 || exhausted != racers-3 {
		t.Fatalf("oversubscription: %d succeeded (want 3), %d exhausted (want %d)", ok, exhausted, racers-3)
	}
	if u, _ := r.GetSeatUsage(ctx(), p, "", "race"); u.Used != 3 {
		t.Fatalf("post-race used = %d, want 3", u.Used)
	}
}
