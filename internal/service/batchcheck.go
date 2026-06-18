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

// BatchCheckResult is index-aligned to the request items. Err is non-empty for
// an item-SPECIFIC condition that does not implicate the rest of the batch: a
// VALIDATION failure (bad arguments) or per-item budget EXHAUSTION (this item's
// model graph is too deep/branching/cyclic). Allowed is then false. SYSTEMIC
// storage/engine failures are NOT reported here — they abort the whole batch
// (see BatchCheck) so a backend outage surfaces as an RPC error instead of
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
// Error policy: an ITEM-SPECIFIC error is isolated to that item's result so its
// siblings still return — this covers a VALIDATION error (ErrInvalidArgument)
// and per-item budget EXHAUSTION (ErrResourceExhausted: this one item's model
// graph is too deep/branching/cyclic, which says nothing about the others). Any
// OTHER error (a systemic storage/engine failure) aborts the whole batch and is
// returned, so an outage is visible as an RPC error rather than swallowed into a
// 200 response of per-item error strings.
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
		case errors.Is(err, ErrInvalidArgument), errors.Is(err, ErrResourceExhausted):
			results[i] = BatchCheckResult{Err: err}
		default:
			return nil, err
		}
	}
	return results, nil
}
