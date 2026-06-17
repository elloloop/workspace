package connect

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/service"
)

// BatchCheck evaluates many Check questions in one round-trip. The request is
// capped at maxBatchCheckItems; results are index-aligned to items. A per-item
// VALIDATION error is reported in that item's result, but an internal failure
// aborts the whole call with a non-OK status (so an outage is not hidden in a
// 200 body of per-item error strings).
func (h *Handler) BatchCheck(ctx context.Context, req *connect.Request[workspacev1.BatchCheckRequest]) (*connect.Response[workspacev1.BatchCheckResponse], error) {
	start := time.Now()
	defer func() { h.metrics.observe("BatchCheck", start) }()

	items := req.Msg.Items
	if h.maxBatchCheckItems > 0 && len(items) > h.maxBatchCheckItems {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("batch_check: %d items exceeds max %d", len(items), h.maxBatchCheckItems))
	}
	h.metrics.observeBatchItems(len(items))
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

	results, err := h.svc.BatchCheck(ctx, p, svcItems)
	if err != nil {
		h.metrics.recordError("BatchCheck")
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.BatchCheckResult, 0, len(results))
	for i, r := range results {
		res := &workspacev1.BatchCheckResult{Allowed: r.Allowed}
		if r.Err != nil {
			res.Error = r.Err.Error()
			h.metrics.recordError("BatchCheck")
		} else {
			h.metrics.recordDecision(items[i].Namespace, items[i].Relation, r.Allowed)
		}
		out = append(out, res)
	}
	return connect.NewResponse(&workspacev1.BatchCheckResponse{Results: out}), nil
}
