package service

import "context"

// BatchCheckItem is one permission question in a BatchCheck.
type BatchCheckItem struct {
	Namespace     string
	ObjectID      string
	Relation      string
	SubjectUserID string
}

// BatchCheckResult is index-aligned to the request items. Err is non-empty
// when the item could not be evaluated; Allowed is then false.
type BatchCheckResult struct {
	Allowed bool
	Err     error
}

// BatchCheck evaluates many permission questions for the caller's project and
// tenant in one call, reusing the single-Check path (and its validation) per
// item. A per-item error is captured in that item's result and does NOT fail
// the batch; the returned slice is index-aligned to items.
func (s *Service) BatchCheck(ctx context.Context, p Principal, items []BatchCheckItem) []BatchCheckResult {
	results := make([]BatchCheckResult, len(items))
	for i, it := range items {
		allowed, err := s.Check(ctx, p, it.Namespace, it.ObjectID, it.Relation, it.SubjectUserID)
		results[i] = BatchCheckResult{Allowed: allowed, Err: err}
	}
	return results
}
