package authz

import "context"

// BackstopReason identifies which per-request safety backstop fired during an
// evaluation. Kept to a small, fixed set so metric label cardinality stays low.
type BackstopReason string

const (
	// BackstopDepth: recursion exceeded maxRecursionDepth (a graceful fail-closed
	// deny, not an error).
	BackstopDepth BackstopReason = "depth"
	// BackstopCycle: recursion cycled back to an in-progress ancestor (graceful
	// fail-closed deny).
	BackstopCycle BackstopReason = "cycle"
	// BackstopBudget: the per-request store-read budget was exhausted (an ERROR —
	// ErrEvalBudgetExceeded).
	BackstopBudget BackstopReason = "budget"
)

// Backstops collects which backstops fired during one operation. The engine
// records into it (when one is installed on the context); the connect layer
// reads it after the call to emit metrics. Counting backstops out through the
// context keeps the engine dependency-free (no Prometheus import) and avoids
// changing every Check/Expand return signature.
type Backstops struct {
	Depth  int
	Cycle  int
	Budget int
}

type backstopCtxKey struct{}

// WithBackstops returns a child context carrying a fresh Backstops collector and
// the collector itself. A caller installs it before an engine operation and
// reads the populated counts afterwards. When no collector is installed, the
// engine's recording is a cheap no-op.
func WithBackstops(ctx context.Context) (context.Context, *Backstops) {
	b := &Backstops{}
	return context.WithValue(ctx, backstopCtxKey{}, b), b
}

// recordBackstop bumps the installed collector for reason, or does nothing when
// none is installed. Engine-internal.
func recordBackstop(ctx context.Context, reason BackstopReason) {
	b, _ := ctx.Value(backstopCtxKey{}).(*Backstops)
	if b == nil {
		return
	}
	switch reason {
	case BackstopDepth:
		b.Depth++
	case BackstopCycle:
		b.Cycle++
	case BackstopBudget:
		b.Budget++
	}
}
