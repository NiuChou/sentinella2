package knowledge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/perseworks/sentinella2/pkg/provider"
)

// candidateSchemaVersion is the current schema version for candidate YAML files.
const candidateSchemaVersion = "1.0"

// Synthesizer uses an LLM to analyze vulnerability data and generate candidate
// pattern/case entries for the knowledge base. It is model-agnostic: any
// provider.Provider implementation works (Anthropic, OpenAI, Ollama, etc.).
type Synthesizer struct {
	llm     provider.Provider
	current KnowledgeBase
}

// NewSynthesizer creates a Synthesizer backed by the given LLM provider and
// existing knowledge base context.
func NewSynthesizer(llm provider.Provider, kb KnowledgeBase) *Synthesizer {
	return &Synthesizer{
		llm:     llm,
		current: kb,
	}
}

// PatternCandidate is an LLM-generated candidate for a new pattern or case.
// Candidates go through a review pipeline before being applied to the KB.
type PatternCandidate struct {
	Type        string  `yaml:"type"`         // "new_pattern", "pattern_update", "new_case"
	PatternYAML string  `yaml:"pattern_yaml"` // raw YAML for the suggested pattern
	CaseYAML    string  `yaml:"case_yaml"`    // raw YAML for the suggested case
	SourceID    string  `yaml:"source_id"`    // CVE/GHSA/SA that triggered this
	Rationale   string  `yaml:"rationale"`    // LLM's explanation
	Confidence  float64 `yaml:"confidence"`   // 0.0-1.0
	Status      string  `yaml:"status"`       // "pending_review", "approved", "rejected"
}

// candidateFile is the on-disk YAML representation of a batch of candidates.
type candidateFile struct {
	SchemaVersion string             `yaml:"schema_version"`
	Kind          string             `yaml:"kind"`
	Candidates    []PatternCandidate `yaml:"candidates"`
}

// AnalyzeCVE sends a CVE description to the LLM with existing KB context and
// returns a candidate pattern/case entry. The prompt includes the pattern schema
// and the most similar existing patterns to guide the LLM.
func (s *Synthesizer) AnalyzeCVE(ctx context.Context, entry FeedEntry) (PatternCandidate, error) {
	if entry.SourceID == "" {
		return PatternCandidate{}, fmt.Errorf("analyze cve: source_id must not be empty")
	}

	similar := findSimilarPatterns(s.current, entry.Description, 3)
	prompt := buildAnalysisPrompt(entry, similar)

	resp, err := s.llm.Audit(ctx, provider.AuditRequest{
		SystemPrompt: synthesisSystemPrompt,
		CodeContext:   prompt,
		Pattern:      "knowledge-synthesis",
		Language:      "yaml",
	})
	if err != nil {
		return PatternCandidate{}, fmt.Errorf("analyze cve %s: llm audit: %w", entry.SourceID, err)
	}

	candidate := parseAnalysisResponse(resp.Raw, entry.SourceID)
	return candidate, nil
}

// AnalyzeBatch processes multiple feed entries and returns candidates. Each
// entry is analyzed independently; errors on individual entries are captured in
// the candidate's Rationale field rather than failing the entire batch.
func (s *Synthesizer) AnalyzeBatch(ctx context.Context, entries []FeedEntry) ([]PatternCandidate, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	candidates := make([]PatternCandidate, 0, len(entries))
	var errs []string

	for _, entry := range entries {
		candidate, err := s.AnalyzeCVE(ctx, entry)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", entry.SourceID, err.Error()))
			continue
		}
		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("analyze batch: all entries failed: %s", strings.Join(errs, "; "))
	}

	return candidates, nil
}

// ReviewCandidate asks the LLM to review and validate a candidate. It returns
// an updated candidate with adjusted confidence and rationale. The original
// candidate is not modified.
func (s *Synthesizer) ReviewCandidate(ctx context.Context, candidate PatternCandidate) (PatternCandidate, error) {
	prompt := buildReviewPrompt(candidate)

	resp, err := s.llm.Audit(ctx, provider.AuditRequest{
		SystemPrompt: reviewSystemPrompt,
		CodeContext:   prompt,
		Pattern:      "candidate-review",
		Language:      "yaml",
	})
	if err != nil {
		return PatternCandidate{}, fmt.Errorf("review candidate %s: llm audit: %w", candidate.SourceID, err)
	}

	reviewed := parseReviewResponse(resp.Raw, candidate)
	return reviewed, nil
}

// ApplyApproved writes approved candidates to the stateDir as individual YAML
// files. Only candidates with Status "approved" are written; others are skipped.
func (s *Synthesizer) ApplyApproved(candidates []PatternCandidate, stateDir string) error {
	if stateDir == "" {
		return fmt.Errorf("apply approved: state directory must not be empty")
	}

	approved := filterApproved(candidates)
	if len(approved) == 0 {
		return nil
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("apply approved: create directory: %w", err)
	}

	file := candidateFile{
		SchemaVersion: candidateSchemaVersion,
		Kind:          "candidates",
		Candidates:    approved,
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("apply approved: marshal yaml: %w", err)
	}

	path := filepath.Join(stateDir, "approved-candidates.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("apply approved: write file: %w", err)
	}

	return nil
}

// --- prompt builders ---

// synthesisSystemPrompt instructs the LLM to act as a security knowledge
// engineer. It is model-agnostic: no XML tags, standard markdown only.
const synthesisSystemPrompt = `You are a security knowledge engineer for sentinella2, a security audit engine.

Your task is to analyze vulnerability advisories (CVEs, GHSAs, FreeBSD SAs) and generate
structured YAML entries that follow the sentinella2 knowledge base schema.

You always output valid YAML. You never invent data that is not supported by the advisory.
You assign confidence scores honestly based on how well the advisory maps to a detection pattern.`

// reviewSystemPrompt instructs the LLM to validate a candidate entry.
const reviewSystemPrompt = `You are a senior security engineer reviewing candidate entries for the
sentinella2 knowledge base.

Evaluate the candidate YAML for:
1. YAML structure validity
2. False positive potential (are the detection rules too broad or too narrow?)
3. Severity accuracy (does the severity match the actual impact?)
4. Completeness (are required fields present and meaningful?)

Return your assessment as YAML with fields: confidence (0.0-1.0), rationale (string),
and issues (list of strings). Be conservative with confidence scores.`

// buildAnalysisPrompt constructs the full analysis prompt from a feed entry and
// similar existing patterns.
func buildAnalysisPrompt(entry FeedEntry, similar []Pattern) string {
	var b strings.Builder

	b.WriteString("# Vulnerability Advisory Analysis\n\n")
	b.WriteString("## sentinella2 Pattern Schema\n\n")
	b.WriteString(patternSchemaDoc)
	b.WriteString("\n\n")

	if len(similar) > 0 {
		b.WriteString("## Similar Existing Patterns\n\n")
		b.WriteString("These patterns from the current knowledge base are most similar ")
		b.WriteString("to the advisory below. Use them as reference for style and structure.\n\n")
		for i, p := range similar {
			fmt.Fprintf(&b, "### Pattern %d: %s\n\n", i+1, p.Name)
			fmt.Fprintf(&b, "- ID: %s\n", p.ID)
			fmt.Fprintf(&b, "- Severity: %s\n", p.Severity)
			fmt.Fprintf(&b, "- Description: %s\n", p.Description)
			fmt.Fprintf(&b, "- Detection abstract: %s\n", p.Detection.Abstract)
			fmt.Fprintf(&b, "- Fix abstract: %s\n\n", p.Fix.Abstract)
		}
	}

	b.WriteString("## Advisory to Analyze\n\n")
	fmt.Fprintf(&b, "- Source ID: %s\n", entry.SourceID)
	fmt.Fprintf(&b, "- Source: %s\n", entry.Source)
	fmt.Fprintf(&b, "- Title: %s\n", entry.Title)
	fmt.Fprintf(&b, "- Severity: %s\n", entry.Severity)
	if len(entry.CWEs) > 0 {
		fmt.Fprintf(&b, "- CWEs: %s\n", strings.Join(entry.CWEs, ", "))
	}
	if len(entry.AffectedPkg) > 0 {
		fmt.Fprintf(&b, "- Affected packages: %s\n", strings.Join(entry.AffectedPkg, ", "))
	}
	fmt.Fprintf(&b, "- Description: %s\n\n", entry.Description)

	b.WriteString("## Instructions\n\n")
	b.WriteString("Based on the advisory above, generate ONE of the following:\n\n")
	b.WriteString("1. A `new_pattern` if this represents a vulnerability class not covered ")
	b.WriteString("by existing patterns\n")
	b.WriteString("2. A `pattern_update` if this adds detection rules to an existing pattern\n")
	b.WriteString("3. A `new_case` if this is a specific instance of an existing pattern\n\n")
	b.WriteString("Output your response as YAML with these fields:\n\n")
	b.WriteString("```yaml\n")
	b.WriteString("type: \"new_pattern\" | \"pattern_update\" | \"new_case\"\n")
	b.WriteString("pattern_yaml: |\n  # full pattern YAML if type is new_pattern or pattern_update\n")
	b.WriteString("case_yaml: |\n  # full case YAML if type is new_case\n")
	b.WriteString("source_id: \"the advisory ID\"\n")
	b.WriteString("rationale: \"why you chose this type and these values\"\n")
	b.WriteString("confidence: 0.0-1.0\n")
	b.WriteString("```\n")

	return b.String()
}

// patternSchemaDoc describes the sentinella2 pattern YAML schema for the LLM.
const patternSchemaDoc = `A sentinella2 pattern has this structure:

` + "```yaml" + `
id: "category/short-name"        # unique identifier
name: "Human Readable Name"       # display name
description: "What this pattern detects and why it matters"
severity: CRITICAL | HIGH | MEDIUM | LOW
owasp:                            # OWASP Top 10 references
  - "A03:2021"
freebsd_sa: []                    # FreeBSD SA references (if applicable)
detection:
  abstract: "How to detect this vulnerability"
  tier: 1 | 2 | 3                # 1=regex, 2=context-aware, 3=LLM-deep
  rules:
    go:                           # per-language rules
      pattern: "regex pattern"
      negative_pattern: "regex for already-mitigated code"
      context: "where to look"
  false_positive_hints:
    - "conditions under which this is a false positive"
fix:
  abstract: "How to fix this vulnerability"
  templates:
    go: |
      # code template showing the fix
cases:
  - "case-id-ref"
` + "```" + `

A sentinella2 case has this structure:

` + "```yaml" + `
id: "CASE-NNNN"
title: "Short description"
severity: CRITICAL | HIGH | MEDIUM | LOW
pattern_ref: "category/short-name"
freebsd_sa_ref: ""
location: "file:line or component"
description: "What was found"
fix_summary: "How it was fixed"
lesson: "What we learned"
` + "```"

// buildReviewPrompt constructs the review prompt for a candidate.
func buildReviewPrompt(candidate PatternCandidate) string {
	var b strings.Builder

	b.WriteString("# Candidate Review Request\n\n")
	fmt.Fprintf(&b, "## Source: %s\n\n", candidate.SourceID)
	fmt.Fprintf(&b, "- Type: %s\n", candidate.Type)
	fmt.Fprintf(&b, "- Current confidence: %.2f\n", candidate.Confidence)
	fmt.Fprintf(&b, "- Rationale: %s\n\n", candidate.Rationale)

	if candidate.PatternYAML != "" {
		b.WriteString("## Pattern YAML\n\n```yaml\n")
		b.WriteString(candidate.PatternYAML)
		b.WriteString("\n```\n\n")
	}

	if candidate.CaseYAML != "" {
		b.WriteString("## Case YAML\n\n```yaml\n")
		b.WriteString(candidate.CaseYAML)
		b.WriteString("\n```\n\n")
	}

	b.WriteString("## Review Instructions\n\n")
	b.WriteString("Evaluate this candidate and return YAML:\n\n")
	b.WriteString("```yaml\n")
	b.WriteString("confidence: 0.0-1.0  # your adjusted confidence\n")
	b.WriteString("rationale: \"your assessment\"\n")
	b.WriteString("issues:\n  - \"any problems found\"\n")
	b.WriteString("```\n")

	return b.String()
}

// --- response parsers ---

// parseAnalysisResponse extracts a PatternCandidate from raw LLM output.
// If YAML parsing fails, it returns a low-confidence candidate with the raw
// response preserved in the Rationale field.
func parseAnalysisResponse(raw, sourceID string) PatternCandidate {
	cleaned := extractYAMLBlock(raw)

	var candidate PatternCandidate
	if err := yaml.Unmarshal([]byte(cleaned), &candidate); err != nil {
		return PatternCandidate{
			Type:       "new_case",
			SourceID:   sourceID,
			Rationale:  fmt.Sprintf("failed to parse LLM response: %s\n\nRaw: %s", err.Error(), raw),
			Confidence: 0.1,
			Status:     "pending_review",
		}
	}

	// Ensure required fields.
	if candidate.SourceID == "" {
		candidate.SourceID = sourceID
	}
	if candidate.Status == "" {
		candidate.Status = "pending_review"
	}
	if candidate.Confidence < 0 {
		candidate.Confidence = 0
	}
	if candidate.Confidence > 1 {
		candidate.Confidence = 1
	}

	return candidate
}

// reviewResponse is the expected structure of the LLM's review output.
type reviewResponse struct {
	Confidence float64  `yaml:"confidence"`
	Rationale  string   `yaml:"rationale"`
	Issues     []string `yaml:"issues"`
}

// parseReviewResponse extracts review feedback from raw LLM output and returns
// an updated candidate. The original candidate is not modified.
func parseReviewResponse(raw string, original PatternCandidate) PatternCandidate {
	cleaned := extractYAMLBlock(raw)

	var review reviewResponse
	if err := yaml.Unmarshal([]byte(cleaned), &review); err != nil {
		// If parsing fails, lower confidence and note the failure.
		updated := original
		updated.Confidence = original.Confidence * 0.5
		updated.Rationale = fmt.Sprintf("review parse failed: %s | original: %s", err.Error(), original.Rationale)
		return updated
	}

	updated := original
	updated.Confidence = clampConfidence(review.Confidence)

	if review.Rationale != "" {
		updated.Rationale = review.Rationale
	}

	if len(review.Issues) > 0 {
		updated.Rationale += "\n\nReview issues:\n- " + strings.Join(review.Issues, "\n- ")
	}

	return updated
}

// extractYAMLBlock attempts to extract a YAML code block from markdown-formatted
// LLM output. If no fenced block is found, returns the input as-is.
func extractYAMLBlock(raw string) string {
	// Look for ```yaml ... ``` blocks.
	start := strings.Index(raw, "```yaml")
	if start < 0 {
		start = strings.Index(raw, "```")
	}
	if start < 0 {
		return strings.TrimSpace(raw)
	}

	// Skip past the opening fence line.
	contentStart := strings.Index(raw[start:], "\n")
	if contentStart < 0 {
		return strings.TrimSpace(raw)
	}
	contentStart += start + 1

	end := strings.Index(raw[contentStart:], "```")
	if end < 0 {
		return strings.TrimSpace(raw[contentStart:])
	}

	return strings.TrimSpace(raw[contentStart : contentStart+end])
}

// --- similarity scoring ---

// findSimilarPatterns returns the n patterns from the knowledge base whose
// descriptions have the highest keyword overlap with the given description.
// It uses simple word-frequency intersection scoring.
func findSimilarPatterns(kb KnowledgeBase, description string, n int) []Pattern {
	if n <= 0 || description == "" {
		return nil
	}

	patterns := kb.Patterns()
	if len(patterns) == 0 {
		return nil
	}

	queryWords := tokenize(description)
	if len(queryWords) == 0 {
		return nil
	}

	type scored struct {
		pattern Pattern
		score   float64
	}

	results := make([]scored, 0, len(patterns))
	for _, p := range patterns {
		patternText := p.Name + " " + p.Description + " " + p.Detection.Abstract
		patternWords := tokenize(patternText)
		score := overlapScore(queryWords, patternWords)
		if score > 0 {
			results = append(results, scored{pattern: p, score: score})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if n > len(results) {
		n = len(results)
	}

	out := make([]Pattern, n)
	for i := 0; i < n; i++ {
		out[i] = results[i].pattern
	}
	return out
}

// tokenize splits text into lowercase words, filtering out short stop words.
func tokenize(text string) map[string]int {
	words := make(map[string]int)
	for _, word := range strings.Fields(strings.ToLower(text)) {
		cleaned := strings.Trim(word, ".,;:!?\"'()[]{}/-")
		if len(cleaned) < 3 {
			continue
		}
		if isStopWord(cleaned) {
			continue
		}
		words[cleaned]++
	}
	return words
}

// overlapScore computes a normalized overlap between two word frequency maps.
// It uses the sum of minimum frequencies divided by the size of the query set.
func overlapScore(query, target map[string]int) float64 {
	if len(query) == 0 || len(target) == 0 {
		return 0
	}

	var overlap float64
	for word, qCount := range query {
		if tCount, ok := target[word]; ok {
			minCount := qCount
			if tCount < minCount {
				minCount = tCount
			}
			overlap += float64(minCount)
		}
	}

	return overlap / float64(len(query))
}

// isStopWord returns true for common English words that add noise to similarity.
func isStopWord(w string) bool {
	switch w {
	case "the", "and", "for", "are", "but", "not", "you", "all",
		"can", "has", "her", "was", "one", "our", "out", "that",
		"this", "with", "from", "they", "been", "have", "will",
		"when", "who", "which", "their", "said", "each", "she",
		"how", "use", "may", "its", "also", "into", "than",
		"then", "them", "would", "could", "should", "does":
		return true
	}
	return false
}

// --- helpers ---

// filterApproved returns only candidates with Status "approved".
func filterApproved(candidates []PatternCandidate) []PatternCandidate {
	var approved []PatternCandidate
	for _, c := range candidates {
		if c.Status == "approved" {
			approved = append(approved, c)
		}
	}
	return approved
}

// clampConfidence ensures a confidence value is within [0.0, 1.0].
func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
