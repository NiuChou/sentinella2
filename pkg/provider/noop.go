package provider

import "context"

// NoopProvider returns empty results. Used when no LLM is configured,
// enabling scan-only mode (Tier 1) without requiring an API key.
type NoopProvider struct{}

// Name returns "noop".
func (n *NoopProvider) Name() string {
	return "noop"
}

// Audit returns an empty AuditResponse. No LLM call is made.
func (n *NoopProvider) Audit(_ context.Context, _ AuditRequest) (AuditResponse, error) {
	return AuditResponse{}, nil
}
