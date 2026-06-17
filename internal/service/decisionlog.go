package service

import (
	"context"
	"time"

	"github.com/elloloop/workspace/pkg/authz"
)

// DecisionRecord is one authorization decision, emitted to a DecisionLogger
// after the decision is made. It is append-only audit data and is never
// consulted on the authorization hot path.
type DecisionRecord struct {
	ProjectID string
	TenantID  string
	Namespace string
	ObjectID  string
	Relation  string
	// Subject identifies who the decision was about: exactly one of
	// SubjectUserID (a concrete-user Check) or SubjectSet (a CheckSet) is set.
	SubjectUserID string
	SubjectSet    *authz.SubjectSet
	Allowed       bool
	// Err is non-empty when the decision could not be evaluated.
	Err string
	// Caller is the calling-service identity that asked (e.g. "slack"), for
	// attribution. Empty for an anonymous (flat-token) caller.
	Caller    string
	DecidedAt time.Time
}

// DecisionLogger receives authorization decisions for audit/debugging. An
// implementation MUST be non-blocking and MUST NOT affect the authorization
// result (a logging failure never changes a Check). A nil DecisionLogger
// disables logging with zero hot-path overhead.
type DecisionLogger interface {
	Log(ctx context.Context, rec DecisionRecord)
}

// WithDecisionLogger enables emitting an audit record for every Check/CheckSet
// decision. Passing nil keeps logging disabled.
func WithDecisionLogger(l DecisionLogger) Option {
	return func(s *Service) { s.decisionLog = l }
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
