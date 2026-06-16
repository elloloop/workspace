package service

import (
	"context"
	"errors"
)

// BatchCheckItem is one permission question in a BatchCheck.
type BatchCheckItem struct {
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
}

// BatchCheckResult is index-aligned to the request items. Err is non-empty only
// for a per-item VALIDATION failure (bad arguments); Allowed is then false.
// Internal/storage/engine failures are NOT reported here — they abort the whole
// batch (see BatchCheck) so a backend outage surfaces as an RPC error instead of
// hiding as scattered per-item "error" strings.
type BatchCheckResult struct {
	Allowed bool
	Err     error
}

// BatchCheck evaluates many permission questions for the caller's project and
// tenant, reusing the single-Check path (and its validation) per item. It fans
// out to one Check per item — bounded by the caller's item cap (enforced at the
// transport edge) and the request deadline, which it honors between items so a
// cancelled/timed-out request stops fanning out promptly.
//
// Error policy: a per-item VALIDATION error (ErrInvalidArgument) is isolated to
// that item's result. Any other error (storage/engine failure) aborts the whole
// batch and is returned, so systemic outages are visible as an RPC error rather
// than swallowed into a 200 response.
func (s *Service) BatchCheck(ctx context.Context, p Principal, items []BatchCheckItem) ([]BatchCheckResult, error) {
	results := make([]BatchCheckResult, len(items))
	for i, it := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		allowed, err := s.Check(ctx, p, it.Namespace, it.ObjectID, it.Relation, it.SubjectUserID, nil)
		switch {
		case err == nil:
			results[i] = BatchCheckResult{Allowed: allowed}
		case errors.Is(err, ErrInvalidArgument):
			results[i] = BatchCheckResult{Err: err}
		default:
			return nil, err
		}
	}
	return results, nil
}
