// Package provider abstracts LLM API calls for deep security auditing.
// Implementations exist for OpenAI-compatible APIs (covering Anthropic, OpenAI,
// GLM, Ollama, and others) and a no-op provider for scan-only mode.
package provider

import (
	"context"
	"fmt"
)

// Provider abstracts LLM API calls for deep security audit.
type Provider interface {
	// Audit sends a security audit prompt to the LLM and returns structured findings.
	Audit(ctx context.Context, req AuditRequest) (AuditResponse, error)
	// Name returns the provider name (e.g., "openai-compatible", "noop").
	Name() string
}

// AuditRequest describes what the LLM should audit.
type AuditRequest struct {
	SystemPrompt string // Security auditor role + knowledge context
	CodeContext   string // Code to audit
	Pattern      string // Which vulnerability pattern to check
	Language     string // Programming language of the code
}

// AuditResponse holds the LLM's audit output.
type AuditResponse struct {
	Findings []AuditFinding
	Raw      string // Raw LLM response for debugging
}

// AuditFinding is a single vulnerability found by the LLM.
type AuditFinding struct {
	PatternRef    string  `json:"pattern_ref"`
	Severity      string  `json:"severity"`
	File          string  `json:"file"`
	Line          int     `json:"line"`
	Description   string  `json:"description"`
	FixSuggestion string  `json:"fix_suggestion"`
	Confidence    float64 `json:"confidence"` // 0.0-1.0
}

// Config holds provider configuration.
type Config struct {
	Name    string // "openai-compatible", "noop", or "" (defaults to noop)
	BaseURL string // API base URL (for openai-compatible)
	Model   string // Model name (e.g., "claude-sonnet-4-20250514", "gpt-4o")
	APIKey  string // API key (from env var, not hardcoded)
}

// New creates a Provider from config. Returns noop if config.Name is empty.
func New(cfg Config) (Provider, error) {
	switch cfg.Name {
	case "", "noop":
		return &NoopProvider{}, nil
	case "openai-compatible":
		return newOpenAIProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown provider %q: valid providers are openai-compatible, noop", cfg.Name)
	}
}
