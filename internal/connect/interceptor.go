package connect

import (
	"context"

	"connectrpc.com/connect"

	"github.com/elloloop/workspace/pkg/authz"
)

// backstopInterceptor installs a fresh engine-backstop collector on the request
// context for EVERY RPC and records the backstops that fired after the handler
// returns. Installing it centrally — rather than per handler — means any engine
// evaluation is covered regardless of entrypoint: the data-plane surfaces
// (Check/CheckSet/Expand/ListObjects/BatchCheck) AND the product-surface RPCs
// (CreateWorkspace/AddMember/…) that drive a check through Service.allowed feed
// authz_eval_backstop_total, and any FUTURE engine-check entrypoint is covered
// automatically. The collector counts once per reason per request, so the metric
// stays a clean "this request tripped a backstop" indicator.
func backstopInterceptor(m *metrics) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			ctx, backstops := authz.WithBackstops(ctx)
			resp, err := next(ctx, req)
			m.recordBackstops(backstops)
			return resp, err
		}
	}
}

// Interceptors returns the Connect interceptors every service handler installs.
// Exposed so app.New wires them onto each NewXxxServiceHandler via
// connect.WithInterceptors.
func (h *Handler) Interceptors() []connect.Interceptor {
	return []connect.Interceptor{backstopInterceptor(h.metrics)}
}
