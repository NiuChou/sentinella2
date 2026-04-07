// Package scan provides the core vulnerability scanning engine for sentinella2.
// It supports tiered detection: Tier 1 uses deterministic regex/glob matching,
// Tier 2 uses structural analysis, and Tier 3 delegates to LLM reasoning.
// All result types are immutable value objects.
package scan

import (
	"context"
	"time"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// Scanner scans a project directory for security vulnerabilities.
type Scanner interface {
	Scan(ctx context.Context, targetDir string) (Result, error)
}

// Result holds the immutable results of a scan operation. Fields are
// unexported; use accessor methods to read values.
type Result struct {
	findings     []Finding
	targetDir    string
	patternsUsed int
	filesScanned int
	duration     time.Duration
}

// NewResult constructs an immutable Result. The findings slice is copied
// to prevent external mutation.
func NewResult(
	findings []Finding,
	targetDir string,
	patternsUsed int,
	filesScanned int,
	duration time.Duration,
) Result {
	copied := make([]Finding, len(findings))
	copy(copied, findings)
	return Result{
		findings:     copied,
		targetDir:    targetDir,
		patternsUsed: patternsUsed,
		filesScanned: filesScanned,
		duration:     duration,
	}
}

// Findings returns a copy of all findings.
func (r Result) Findings() []Finding {
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

// FindingsBySeverity returns findings filtered to the given severity level.
func (r Result) FindingsBySeverity(sev knowledge.Severity) []Finding {
	var out []Finding
	for _, f := range r.findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

// TargetDir returns the directory that was scanned.
func (r Result) TargetDir() string { return r.targetDir }

// PatternsUsed returns the number of patterns applied during the scan.
func (r Result) PatternsUsed() int { return r.patternsUsed }

// FilesScanned returns the number of files that were scanned.
func (r Result) FilesScanned() int { return r.filesScanned }

// Duration returns how long the scan took.
func (r Result) Duration() time.Duration { return r.duration }

// Summary returns an aggregate count of findings by severity.
func (r Result) Summary() Summary {
	s := Summary{
		Total:    len(r.findings),
		Files:    r.filesScanned,
		Duration: r.duration,
	}
	for _, f := range r.findings {
		switch f.Severity {
		case knowledge.SeverityCritical:
			s.Critical++
		case knowledge.SeverityHigh:
			s.High++
		case knowledge.SeverityMedium:
			s.Medium++
		case knowledge.SeverityLow:
			s.Low++
		}
	}
	return s
}

// Finding represents a single vulnerability match in a scanned file.
type Finding struct {
	RuleID      string
	PatternRef  string
	Severity    knowledge.Severity
	File        string
	Line        int
	Column      int
	Message     string
	MatchedText string
	Context     string
	FixHint     string
}

// Summary provides aggregate counts from a scan result.
type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
	Files    int
	Duration time.Duration
}

// Option configures the scanner using the functional options pattern.
type Option func(*options)

type options struct {
	kb           knowledge.KnowledgeBase
	maxTier      int
	includeGlobs []string
	excludeGlobs []string
	changedOnly  []string
}

// defaultOptions returns the baseline scanner configuration.
func defaultOptions() options {
	return options{
		maxTier: 1,
		excludeGlobs: []string{
			"**/.git/**",
			"**/node_modules/**",
			"**/vendor/**",
			"**/.terraform/**",
			"**/dist/**",
			"**/build/**",
		},
	}
}

// WithKnowledge sets the knowledge base to use for scanning.
func WithKnowledge(kb knowledge.KnowledgeBase) Option {
	return func(o *options) { o.kb = kb }
}

// WithMaxTier sets the maximum detection tier (1, 2, or 3).
// Tier 1 is deterministic regex matching. Default is 1.
func WithMaxTier(tier int) Option {
	return func(o *options) {
		if tier >= 1 && tier <= 3 {
			o.maxTier = tier
		}
	}
}

// WithInclude adds file glob patterns to include in the scan.
// Only files matching at least one include pattern will be scanned.
func WithInclude(globs ...string) Option {
	return func(o *options) {
		o.includeGlobs = append(o.includeGlobs, globs...)
	}
}

// WithExclude adds file glob patterns to exclude from the scan.
// Excluded files are skipped even if they match an include pattern.
func WithExclude(globs ...string) Option {
	return func(o *options) {
		o.excludeGlobs = append(o.excludeGlobs, globs...)
	}
}

// WithChangedOnly limits the scan to only the specified file paths.
// Useful for incremental scanning in CI pipelines.
func WithChangedOnly(files ...string) Option {
	return func(o *options) {
		o.changedOnly = append(o.changedOnly, files...)
	}
}
