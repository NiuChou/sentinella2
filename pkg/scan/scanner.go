// Package scan provides the core vulnerability scanning engine for sentinella2.
// It supports tiered detection: Tier 1 uses deterministic regex/glob matching,
// Tier 2 uses structural analysis, and Tier 3 delegates to LLM reasoning.
// All result types are immutable value objects.
package scan

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// msgNormPatterns are applied in order to replace specific runtime values
// (HTTP methods+paths, variable names, quoted strings, numbers) with stable
// placeholders so that the stable ID does not change when irrelevant details vary.
var msgNormPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+\S+`), "<HTTP_METHOD_PATH>"},
	{regexp.MustCompile(`/[a-zA-Z0-9_\-./]+`), "<PATH>"},
	{regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\S+`), "<VAR_ASSIGN>"},
	{regexp.MustCompile(`"[^"]*"`), "<STR>"},
	{regexp.MustCompile(`'[^']*'`), "<STR>"},
	{regexp.MustCompile(`\b\d+\b`), "<NUM>"},
}

// normalizeMessage replaces variable runtime values with stable placeholders.
func normalizeMessage(msg string) string {
	out := msg
	for _, p := range msgNormPatterns {
		out = p.re.ReplaceAllString(out, p.replacement)
	}
	return out
}

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
	// Confidence is a [0,1] probability that this finding is a true positive.
	// Defaults to 0; calibrated by the Bayesian tuner once feedback accumulates.
	Confidence float64
}

// StableID returns a deterministic identifier for this finding that is stable
// across code movement. It is based on PatternRef, the file path relative to
// rootDir, and a normalised form of the message (specific values replaced with
// placeholders). Line number is intentionally excluded so the ID survives
// refactoring that shifts code without changing its substance.
//
// Format: "{PatternRef}-{hex8}" where hex8 is the first 8 hex characters of
// sha256(patternRef + "\x00" + relPath + "\x00" + normalizedMessage).
func (f Finding) StableID(rootDir string) string {
	relPath := f.File
	if rootDir != "" {
		if rel, err := filepath.Rel(rootDir, f.File); err == nil {
			relPath = filepath.ToSlash(rel)
		} else {
			relPath = filepath.ToSlash(f.File)
		}
	}

	norm := normalizeMessage(f.Message)
	input := f.PatternRef + "\x00" + relPath + "\x00" + norm
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%s-%x", f.PatternRef, sum[:4])
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
	calibration    *knowledge.CalibrationStore
	memories       *knowledge.MemoryStore
	correlationCfg *CorrelationConfig
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

// WithCorrelation enables cross-scanner correlation adjustment with the given config.
func WithCorrelation(cfg CorrelationConfig) Option {
	return func(o *options) {
		c := cfg
		o.correlationCfg = &c
	}
}

// WithCalibration attaches a CalibrationStore to the scanner so that
// per-bucket Bayesian confidence values are applied to each finding.
func WithCalibration(cs *knowledge.CalibrationStore) Option {
	return func(o *options) { o.calibration = cs }
}

// WithMemories attaches a MemoryStore to the scanner so that
// scanner-scoped memories can suppress patterns on matching files.
func WithMemories(ms *knowledge.MemoryStore) Option {
	return func(o *options) { o.memories = ms }
}
