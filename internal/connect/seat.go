package connect

import (
	"context"
	"math"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// i32 saturates a seat count/limit to int32 for the wire (counts are
// non-negative and realistically tiny; the clamp is a defensive guard).
func i32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < 0 {
		return 0
	}
	return int32(n)
}

// SeatService is project/tenant-scoped infrastructure (like AuthzService): the
// calling service is the trust boundary, so there is no acting-user check; the
// subject is request data. Writes are subject to the per-tenant rate limit and
// fail closed on a suspended project (enforced in the service layer).

func (h *Handler) SetSeatLimit(ctx context.Context, req *connect.Request[workspacev1.SetSeatLimitRequest]) (*connect.Response[workspacev1.SetSeatLimitResponse], error) {
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	lim, err := h.svc.SetSeatLimit(ctx, p, req.Msg.Sku, int(req.Msg.Limit))
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.SetSeatLimitResponse{
		Limit: &workspacev1.SeatLimit{Sku: lim.SKU, Limit: i32(lim.Limit)},
	}), nil
}

func (h *Handler) GetSeatUsage(ctx context.Context, req *connect.Request[workspacev1.GetSeatUsageRequest]) (*connect.Response[workspacev1.GetSeatUsageResponse], error) {
	p := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	u, err := h.svc.SeatUsage(ctx, p, req.Msg.Sku)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.GetSeatUsageResponse{
		Sku: u.SKU, Used: i32(u.Used), Limit: i32(u.Limit), Limited: u.Limited,
	}), nil
}

func (h *Handler) AssignSeat(ctx context.Context, req *connect.Request[workspacev1.AssignSeatRequest]) (*connect.Response[workspacev1.AssignSeatResponse], error) {
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	alreadyHeld, err := h.svc.AssignSeat(ctx, p, req.Msg.Sku, req.Msg.UserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.AssignSeatResponse{AlreadyHeld: alreadyHeld}), nil
}

func (h *Handler) RevokeSeat(ctx context.Context, req *connect.Request[workspacev1.RevokeSeatRequest]) (*connect.Response[workspacev1.RevokeSeatResponse], error) {
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err := h.svc.RevokeSeat(ctx, p, req.Msg.Sku, req.Msg.UserId); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.RevokeSeatResponse{}), nil
}

func (h *Handler) ListSeats(ctx context.Context, req *connect.Request[workspacev1.ListSeatsRequest]) (*connect.Response[workspacev1.ListSeatsResponse], error) {
	p := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	seats, err := h.svc.ListSeats(ctx, p, req.Msg.Sku)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.SeatAssignment, 0, len(seats))
	for _, a := range seats {
		out = append(out, &workspacev1.SeatAssignment{
			Sku: a.SKU, UserId: a.UserID, AssignedAt: timestamppb.New(a.AssignedAt),
		})
	}
	return connect.NewResponse(&workspacev1.ListSeatsResponse{Seats: out}), nil
}
