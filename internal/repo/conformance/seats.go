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

// limPtr is the *int a seat limit is set with (nil clears it / unlimited).
func limPtr(n int) *int { return &n }

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
	if err := r.SetSeatLimit(ctx(), p, "", "pro", limPtr(2)); err != nil {
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
	if err := r.SetSeatLimit(ctx(), p, "", "race", limPtr(3)); err != nil {
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

// testSeatLimitSemantics pins limit=0 (admits none), clearing back to unlimited,
// the downgrade contract (cap below usage is allowed; further assigns denied),
// idempotent-reassign self-heal of the backing tuple, and that deprovisioning a
// user frees their seats.
func testSeatLimitSemantics(t *testing.T, r service.Repository) {
	t.Helper()
	const p = "proj"
	now := time.Now().UTC()
	assign := func(sku, user string) (bool, error) {
		return r.AssignSeatAndTuple(ctx(), &service.SeatAssignment{ProjectID: p, SKU: sku, UserID: user, AssignedAt: now}, seatTup(sku, user))
	}

	// limit 0 admits no seats.
	if err := r.SetSeatLimit(ctx(), p, "", "none", limPtr(0)); err != nil {
		t.Fatalf("SetSeatLimit 0: %v", err)
	}
	if _, err := assign("none", "u1"); !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("limit 0 must admit nobody, got %v", err)
	}
	// Clearing the limit (nil) returns the sku to unlimited.
	if err := r.SetSeatLimit(ctx(), p, "", "none", nil); err != nil {
		t.Fatalf("clear limit: %v", err)
	}
	if u, _ := r.GetSeatUsage(ctx(), p, "", "none"); u.Limited {
		t.Fatalf("cleared limit must be unlimited, got %+v", u)
	}
	if held, err := assign("none", "u1"); err != nil || held {
		t.Fatalf("assign after clear: held=%v err=%v", held, err)
	}

	// Downgrade: cap "dg" at 3, fill it, then lower below usage → allowed.
	if err := r.SetSeatLimit(ctx(), p, "", "dg", limPtr(3)); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"a", "b", "c"} {
		if _, err := assign("dg", u); err != nil {
			t.Fatalf("fill dg %s: %v", u, err)
		}
	}
	if err := r.SetSeatLimit(ctx(), p, "", "dg", limPtr(1)); err != nil {
		t.Fatalf("downgrade below usage must succeed: %v", err)
	}
	if u, _ := r.GetSeatUsage(ctx(), p, "", "dg"); u.Used != 3 || u.Limit != 1 {
		t.Fatalf("after downgrade usage = %+v, want used=3 limit=1 (over-cap)", u)
	}
	if _, err := assign("dg", "d"); !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("over-cap assign must be denied, got %v", err)
	}
	// Revoke down to below the new cap → an assign fits again.
	for _, u := range []string{"a", "b", "c"} {
		if err := r.RevokeSeatAndTuple(ctx(), p, "", "dg", u, seatTup("dg", u)); err != nil {
			t.Fatalf("revoke dg %s: %v", u, err)
		}
	}
	if held, err := assign("dg", "d"); err != nil || held {
		t.Fatalf("assign after revoking below cap: held=%v err=%v", held, err)
	}

	// Self-heal: delete the backing tuple out-of-band, re-assign (idempotent) →
	// the tuple is re-asserted so the seat grants access again.
	if err := r.WriteTuples(ctx(), p, "", nil, []authz.Tuple{seatTup("dg", "d")}); err != nil {
		t.Fatalf("delete tuple out-of-band: %v", err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "seat", "dg", service.SeatRelation); len(subs) != 0 {
		t.Fatalf("tuple should be gone before re-assign: %d", len(subs))
	}
	if held, err := assign("dg", "d"); err != nil || !held {
		t.Fatalf("re-assign of seated user: held=%v err=%v (want held=true)", held, err)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "seat", "dg", service.SeatRelation); len(subs) != 1 {
		t.Fatalf("re-assign must self-heal the backing tuple, got %d holders", len(subs))
	}

	// Deprovision frees the user's seats project-wide.
	if err := r.SetSeatLimit(ctx(), p, "", "dep", limPtr(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := assign("dep", "leaver"); err != nil {
		t.Fatalf("assign leaver: %v", err)
	}
	if _, err := assign("dep", "other"); !errors.Is(err, service.ErrResourceExhausted) {
		t.Fatalf("dep should be full, got %v", err)
	}
	if _, err := r.DeleteAllSubjectTuplesInProject(ctx(), p, "leaver"); err != nil {
		t.Fatalf("DeprovisionUser: %v", err)
	}
	if u, _ := r.GetSeatUsage(ctx(), p, "", "dep"); u.Used != 0 {
		t.Fatalf("deprovision must free the seat, used = %d", u.Used)
	}
	if subs, _ := r.ListSubjects(ctx(), p, "", "seat", "dep", service.SeatRelation); len(subs) != 0 {
		t.Fatalf("deprovisioned seat tuple not removed: %d", len(subs))
	}
	if held, err := assign("dep", "other"); err != nil || held {
		t.Fatalf("seat freed by deprovision must be reusable: held=%v err=%v", held, err)
	}
}

// testSeatIsolation pins that seat caps and assignments are independent across
// tenants of a project and across projects (a billing-domain guarantee).
func testSeatIsolation(t *testing.T, r service.Repository) {
	t.Helper()
	const pA, pB = "projA", "projB"
	const tA, tB = "tenantA", "tenantB"
	now := time.Now().UTC()
	assign := func(proj, tenant, sku, user string) (bool, error) {
		return r.AssignSeatAndTuple(ctx(), &service.SeatAssignment{ProjectID: proj, TenantID: tenant, SKU: sku, UserID: user, AssignedAt: now}, seatTup(sku, user))
	}

	// (projA, tenantA): cap "pro" at 1 and fill it.
	if err := r.SetSeatLimit(ctx(), pA, tA, "pro", limPtr(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := assign(pA, tA, "pro", "alice"); err != nil {
		t.Fatalf("fill A/tA: %v", err)
	}

	// tenantB of the same project has an INDEPENDENT (unlimited) cap → assign OK.
	if u, _ := r.GetSeatUsage(ctx(), pA, tB, "pro"); u.Used != 0 || u.Limited {
		t.Fatalf("tenantB usage must be 0/unlimited, got %+v", u)
	}
	if held, err := assign(pA, tB, "pro", "bob"); err != nil || held {
		t.Fatalf("tenantB assign must succeed independently: held=%v err=%v", held, err)
	}
	// A's cap is untouched.
	if u, _ := r.GetSeatUsage(ctx(), pA, tA, "pro"); u.Used != 1 {
		t.Fatalf("tenantA usage must still be 1, got %+v", u)
	}
	if seats, _ := r.ListSeats(ctx(), pA, tB, "pro"); len(seats) != 1 || seats[0].UserID != "bob" {
		t.Fatalf("ListSeats tenantB = %+v, want only bob", seats)
	}
	// Backing tuples are tenant-scoped.
	if subs, _ := r.ListSubjects(ctx(), pA, tA, "seat", "pro", service.SeatRelation); len(subs) != 1 || subs[0].UserID != "alice" {
		t.Fatalf("tenantA seat tuple = %+v, want alice", subs)
	}
	if subs, _ := r.ListSubjects(ctx(), pA, tB, "seat", "pro", service.SeatRelation); len(subs) != 1 || subs[0].UserID != "bob" {
		t.Fatalf("tenantB seat tuple = %+v, want bob", subs)
	}

	// Different PROJECT, same tenant id: also independent.
	if u, _ := r.GetSeatUsage(ctx(), pB, tA, "pro"); u.Used != 0 || u.Limited {
		t.Fatalf("projB usage must be 0/unlimited, got %+v", u)
	}
	if held, err := assign(pB, tA, "pro", "carol"); err != nil || held {
		t.Fatalf("projB assign must succeed independently: held=%v err=%v", held, err)
	}
}
