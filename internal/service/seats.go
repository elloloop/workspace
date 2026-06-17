package service

import (
	"context"
	"fmt"

	"github.com/elloloop/workspace/pkg/authz"
)

// seatNamespace is the RESERVED namespace for seat-holder tuples. It is rejected
// by the generic tuple-write path (validateTuple), so a `seat:<sku>#holder@user`
// tuple can only be minted/removed via the cap-enforced AssignSeat/RevokeSeat —
// the seat count and the granted access can never diverge.
const seatNamespace = "seat"

// SeatRelation is the relation a seat assignment grants in the `seat` namespace:
// a `seat:<sku>#holder@user:<id>` tuple, so a product model can gate access on
// seat-holding (the `seat` namespace falls back to direct tuples by default).
const SeatRelation = "holder"

// seatTuple builds the backing relation tuple for a (sku, user) seat.
func seatTuple(sku, userID string) authz.Tuple {
	return authz.Tuple{Namespace: seatNamespace, ObjectID: sku, Relation: SeatRelation, Subject: authz.Subject{UserID: userID}}
}

// SetSeatLimit configures the seat cap for a sku in the caller's project/tenant.
// A non-nil limit must be >= 0 (0 admits no seats); a NIL limit CLEARS the cap,
// returning the sku to unlimited. Lowering a limit below current usage is allowed
// (a downgrade): it succeeds, SeatUsage then reports used > limit, and further
// AssignSeat is denied until seats are revoked below the new cap; existing
// assignments are never auto-revoked. Fails closed on a suspended project.
func (s *Service) SetSeatLimit(ctx context.Context, p Principal, sku string, limit *int) (*SeatLimit, error) {
	if sku == "" {
		return nil, fmt.Errorf("%w: sku is required", ErrInvalidArgument)
	}
	if limit != nil && *limit < 0 {
		return nil, fmt.Errorf("%w: seat limit must be >= 0", ErrInvalidArgument)
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return nil, err
	}
	if err := s.repo.SetSeatLimit(ctx, p.ProjectID, p.TenantID, sku, limit); err != nil {
		return nil, err
	}
	out := &SeatLimit{SKU: sku}
	if limit != nil {
		out.Limit, out.Limited = *limit, true
	}
	return out, nil
}

// SeatLimit is the configured cap for a sku. Limited is false when the sku is
// unlimited (no cap configured), in which case Limit is 0 and meaningless.
type SeatLimit struct {
	SKU     string
	Limit   int
	Limited bool
}

// SeatUsage returns the seat consumption and configured cap for a sku.
func (s *Service) SeatUsage(ctx context.Context, p Principal, sku string) (SeatUsage, error) {
	if sku == "" {
		return SeatUsage{}, fmt.Errorf("%w: sku is required", ErrInvalidArgument)
	}
	return s.repo.GetSeatUsage(ctx, p.ProjectID, p.TenantID, sku)
}

// AssignSeat grants a seat for sku to userID, enforcing the sku's cap at write
// time: it returns ErrResourceExhausted (and assigns nothing) once the cap is
// reached. Re-assigning a user who already holds a seat is idempotent and
// consumes no extra seat (alreadyHeld=true). Fails closed on a suspended
// project. The count-check and insert are atomic in the repository.
func (s *Service) AssignSeat(ctx context.Context, p Principal, sku, userID string) (alreadyHeld bool, err error) {
	if sku == "" || userID == "" {
		return false, fmt.Errorf("%w: sku and user_id are required", ErrInvalidArgument)
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return false, err
	}
	a := &SeatAssignment{
		ProjectID: p.ProjectID, TenantID: p.TenantID, SKU: sku, UserID: userID, AssignedAt: s.now(),
	}
	return s.repo.AssignSeatAndTuple(ctx, a, seatTuple(sku, userID))
}

// RevokeSeat frees userID's seat for sku (and deletes its backing tuple).
// Revoking a seat the user does not hold is a no-op. Fails closed on a
// suspended project.
func (s *Service) RevokeSeat(ctx context.Context, p Principal, sku, userID string) error {
	if sku == "" || userID == "" {
		return fmt.Errorf("%w: sku and user_id are required", ErrInvalidArgument)
	}
	if err := s.ensureProjectActive(ctx, p); err != nil {
		return err
	}
	return s.repo.RevokeSeatAndTuple(ctx, p.ProjectID, p.TenantID, sku, userID, seatTuple(sku, userID))
}

// ListSeats returns the seat assignments for a sku.
func (s *Service) ListSeats(ctx context.Context, p Principal, sku string) ([]*SeatAssignment, error) {
	if sku == "" {
		return nil, fmt.Errorf("%w: sku is required", ErrInvalidArgument)
	}
	return s.repo.ListSeats(ctx, p.ProjectID, p.TenantID, sku)
}
