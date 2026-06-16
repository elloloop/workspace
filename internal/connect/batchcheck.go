package connect

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/service"
)

// BatchCheck evaluates many Check questions in one round-trip. The request is
// capped at maxBatchCheckItems; results are index-aligned to items, and a
// per-item evaluation error is reported in that item's result.
func (h *Handler) BatchCheck(ctx context.Context, req *connect.Request[workspacev1.BatchCheckRequest]) (*connect.Response[workspacev1.BatchCheckResponse], error) {
	items := req.Msg.Items
	if h.maxBatchCheckItems > 0 && len(items) > h.maxBatchCheckItems {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("batch_check: %d items exceeds max %d", len(items), h.maxBatchCheckItems))
	}
	p := h.scope(req.Msg.ProjectId, req.Msg.TenantId)

	svcItems := make([]service.BatchCheckItem, len(items))
	for i, it := range items {
		svcItems[i] = service.BatchCheckItem{
			Namespace:     it.Namespace,
			ObjectID:      it.ObjectId,
			Relation:      it.Relation,
			SubjectUserID: it.SubjectUserId,
		}
	}

	out := make([]*workspacev1.BatchCheckResult, 0, len(items))
	for _, r := range h.svc.BatchCheck(ctx, p, svcItems) {
		res := &workspacev1.BatchCheckResult{Allowed: r.Allowed}
		if r.Err != nil {
			res.Error = r.Err.Error()
		}
		out = append(out, res)
	}
	return connect.NewResponse(&workspacev1.BatchCheckResponse{Results: out}), nil
}
