package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/report"
	"github.com/perseworks/sentinella2/pkg/scan"
)

// scanTimeout is the maximum duration for a single scan operation.
const scanTimeout = 5 * time.Minute

// executeScan runs the Tier 1 deterministic security scanner on the
// specified path and returns the formatted results.
func (s *MCPServer) executeScan(args map[string]interface{}) (string, error) {
	path, err := requireStringArg(args, "path")
	if err != nil {
		return "", err
	}

	format := optionalStringArg(args, "format", "text")
	reporter, err := parseReporter(format)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	scanner := scan.New(
		scan.WithKnowledge(s.kb),
		scan.WithMaxTier(1),
	)

	result, err := scanner.Scan(ctx, path)
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	var buf bytes.Buffer
	if err := reporter.Report(&buf, result); err != nil {
		return "", fmt.Errorf("formatting scan results: %w", err)
	}

	return buf.String(), nil
}

// executeCheckLayers runs the 6-layer defense-in-depth assessment
// and returns the formatted results.
func (s *MCPServer) executeCheckLayers(args map[string]interface{}) (string, error) {
	path, err := requireStringArg(args, "path")
	if err != nil {
		return "", err
	}

	format := optionalStringArg(args, "format", "text")
	reporter, err := parseReporter(format)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	result, err := scan.ScanDefenseLayers(ctx, path, s.kb)
	if err != nil {
		return "", fmt.Errorf("defense layer scan failed: %w", err)
	}

	var buf bytes.Buffer
	if err := reporter.ReportLayers(&buf, result); err != nil {
		return "", fmt.Errorf("formatting layer results: %w", err)
	}

	return buf.String(), nil
}

// executeListPatterns returns the pattern catalog from the knowledge base,
// optionally filtered by severity and/or detection tier.
func (s *MCPServer) executeListPatterns(args map[string]interface{}) (string, error) {
	severityFilter := optionalStringArg(args, "severity", "all")
	tierFilter := optionalIntArg(args, "tier", 0)

	patterns := s.kb.Patterns()
	filtered := filterPatterns(patterns, severityFilter, tierFilter)

	if len(filtered) == 0 {
		return "No patterns match the specified filters.", nil
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("Found %d patterns:\n\n", len(filtered)))

	for _, p := range filtered {
		writePatternSummary(&buf, p)
	}

	return buf.String(), nil
}

// executeGetCase returns detailed information about a specific
// vulnerability case from the knowledge base.
func (s *MCPServer) executeGetCase(args map[string]interface{}) (string, error) {
	id, err := requireStringArg(args, "id")
	if err != nil {
		return "", err
	}

	cases := s.kb.Cases()
	caseEntry, found := findCaseByID(cases, id)
	if !found {
		return "", fmt.Errorf("case %q not found in knowledge base", id)
	}

	return formatCaseDetail(caseEntry), nil
}

// --- Argument helpers ---

// requireStringArg extracts a required string parameter from the args map.
func requireStringArg(args map[string]interface{}, key string) (string, error) {
	val, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required parameter: %s", key)
	}
	str, ok := val.(string)
	if !ok || str == "" {
		return "", fmt.Errorf("parameter %q must be a non-empty string", key)
	}
	return str, nil
}

// optionalStringArg extracts an optional string parameter, returning
// the default if absent or empty.
func optionalStringArg(args map[string]interface{}, key, defaultVal string) string {
	val, ok := args[key]
	if !ok {
		return defaultVal
	}
	str, ok := val.(string)
	if !ok || str == "" {
		return defaultVal
	}
	return str
}

// optionalIntArg extracts an optional integer parameter. JSON numbers
// decode as float64, so the conversion handles that case.
func optionalIntArg(args map[string]interface{}, key string, defaultVal int) int {
	val, ok := args[key]
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return defaultVal
	}
}

// parseReporter creates a Reporter for the given format string.
func parseReporter(format string) (report.Reporter, error) {
	f, err := report.ParseFormat(format)
	if err != nil {
		return nil, err
	}
	return report.New(f), nil
}

// --- Pattern filtering ---

// filterPatterns returns a new slice containing only patterns that match
// the severity and tier filters. "all" severity and tier 0 mean no filter.
func filterPatterns(
	patterns []knowledge.Pattern,
	severity string,
	tier int,
) []knowledge.Pattern {
	var out []knowledge.Pattern
	for _, p := range patterns {
		if severity != "all" && string(p.Severity) != severity {
			continue
		}
		if tier > 0 && p.Detection.Tier != tier {
			continue
		}
		out = append(out, p)
	}
	return out
}

// writePatternSummary formats a single pattern entry for the list output.
func writePatternSummary(buf *strings.Builder, p knowledge.Pattern) {
	buf.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", p.Severity, p.Name, p.ID))
	buf.WriteString(fmt.Sprintf("    Tier: %d\n", p.Detection.Tier))
	if len(p.OWASP) > 0 {
		buf.WriteString(fmt.Sprintf("    OWASP: %s\n", strings.Join(p.OWASP, ", ")))
	}
	buf.WriteString(fmt.Sprintf("    %s\n\n", p.Description))
}

// --- Case lookup ---

// findCaseByID searches the cases slice for a matching ID (case-insensitive).
func findCaseByID(cases []knowledge.Case, id string) (knowledge.Case, bool) {
	target := strings.ToUpper(id)
	for _, c := range cases {
		if strings.ToUpper(c.ID) == target {
			return c, true
		}
	}
	return knowledge.Case{}, false
}

// formatCaseDetail renders a detailed view of a vulnerability case.
func formatCaseDetail(c knowledge.Case) string {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("Case %s: %s\n", c.ID, c.Title))
	buf.WriteString(fmt.Sprintf("Severity: %s\n", c.Severity))
	buf.WriteString(fmt.Sprintf("Pattern: %s\n", c.PatternRef))

	if c.FreeBSDSARef != "" {
		buf.WriteString(fmt.Sprintf("FreeBSD SA: %s\n", c.FreeBSDSARef))
	}
	if c.Location != "" {
		buf.WriteString(fmt.Sprintf("Location: %s\n", c.Location))
	}

	buf.WriteString(fmt.Sprintf("\nDescription:\n  %s\n", c.Description))

	if c.FixSummary != "" {
		buf.WriteString(fmt.Sprintf("\nFix:\n  %s\n", c.FixSummary))
	}
	if c.Lesson != "" {
		buf.WriteString(fmt.Sprintf("\nLesson:\n  %s\n", c.Lesson))
	}

	return buf.String()
}

// --- Knowledge base management tools ---

// executeKBFeedback records feedback for a scan finding and persists it
// to the feedback store.
func (s *MCPServer) executeKBFeedback(args map[string]interface{}) (string, error) {
	findingID, err := requireStringArg(args, "finding_id")
	if err != nil {
		return "", err
	}

	verdictStr, err := requireStringArg(args, "verdict")
	if err != nil {
		return "", err
	}

	verdict := knowledge.Verdict(verdictStr)
	if !verdict.IsValid() {
		return "", fmt.Errorf("invalid verdict %q: must be confirmed, false_positive, or missed", verdictStr)
	}

	store, err := knowledge.OpenFeedbackStore(s.feedbackDir)
	if err != nil {
		return "", fmt.Errorf("opening feedback store: %w", err)
	}

	entry := knowledge.FeedbackEntry{
		FindingID:  findingID,
		PatternRef: patternRefFromFindingID(findingID),
		File:       optionalStringArg(args, "file", ""),
		Line:       optionalIntArg(args, "line", 0),
		Verdict:    verdict,
		Reason:     optionalStringArg(args, "reason", ""),
		Timestamp:  time.Now().UTC(),
	}

	if err := store.Add(entry); err != nil {
		return "", fmt.Errorf("recording feedback: %w", err)
	}

	return fmt.Sprintf("Feedback recorded: %s verdict for finding %s", verdictStr, findingID), nil
}

// executeKBStats returns feedback statistics, optionally filtered to a
// single pattern.
func (s *MCPServer) executeKBStats(args map[string]interface{}) (string, error) {
	store, err := knowledge.OpenFeedbackStore(s.feedbackDir)
	if err != nil {
		return "", fmt.Errorf("opening feedback store: %w", err)
	}

	patternFilter := optionalStringArg(args, "pattern", "")

	if patternFilter != "" {
		st := store.StatsForPattern(patternFilter)
		return formatStats([]knowledge.RuleStats{st}), nil
	}

	allStats := store.Stats()
	if len(allStats) == 0 {
		return "No feedback recorded yet.", nil
	}

	return formatStats(allStats), nil
}

// executeKBTune runs feedback-driven rule tuning and returns the results.
// By default it performs a dry run; set dry_run=false to apply changes.
func (s *MCPServer) executeKBTune(args map[string]interface{}) (string, error) {
	dryRun := optionalBoolArg(args, "dry_run", true)

	store, err := knowledge.OpenFeedbackStore(s.feedbackDir)
	if err != nil {
		return "", fmt.Errorf("opening feedback store: %w", err)
	}

	stats := store.Stats()
	if len(stats) == 0 {
		return "No feedback available for tuning. Record feedback with sentinella2_kb_feedback first.", nil
	}

	tuner := knowledge.NewTuner(knowledge.DefaultTuneConfig())
	_, results := tuner.Tune(s.kb, stats)

	var buf strings.Builder
	if dryRun {
		buf.WriteString("Dry run - proposed changes (not applied):\n\n")
	} else {
		buf.WriteString("Tuning results:\n\n")
	}

	changed := 0
	for _, r := range results {
		if r.Action == "unchanged" {
			continue
		}
		changed++
		buf.WriteString(fmt.Sprintf("  [%s] %s\n", r.Action, r.PatternID))
		buf.WriteString(fmt.Sprintf("    Reason: %s\n", r.Reason))
		if r.OldSev != r.NewSev {
			buf.WriteString(fmt.Sprintf("    Severity: %s -> %s\n", r.OldSev, r.NewSev))
		}
		buf.WriteString(fmt.Sprintf("    Confidence: %.2f\n", r.Confidence))
		if len(r.NewHints) > 0 {
			buf.WriteString(fmt.Sprintf("    New hints: %s\n", strings.Join(r.NewHints, "; ")))
		}
		buf.WriteString("\n")
	}

	if changed == 0 {
		buf.WriteString("  No patterns require adjustment based on current feedback.\n")
	} else {
		buf.WriteString(fmt.Sprintf("Total: %d pattern(s) affected out of %d evaluated.\n", changed, len(results)))
	}

	return buf.String(), nil
}

// executeKBSources lists all registered external knowledge sources.
func (s *MCPServer) executeKBSources(args map[string]interface{}) (string, error) {
	registry, err := knowledge.OpenRegistry(s.registryDir)
	if err != nil {
		return "", fmt.Errorf("opening registry: %w", err)
	}

	entries := registry.List()
	if len(entries) == 0 {
		return "No external knowledge sources registered.", nil
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("Registered knowledge sources (%d):\n\n", len(entries)))

	for _, e := range entries {
		status := "enabled"
		if !e.Enabled {
			status = "disabled"
		}
		buf.WriteString(fmt.Sprintf("  %s [%s]\n", e.Name, status))
		buf.WriteString(fmt.Sprintf("    URL: %s\n", e.URL))
		if e.Description != "" {
			buf.WriteString(fmt.Sprintf("    Description: %s\n", e.Description))
		}
		buf.WriteString(fmt.Sprintf("    Added: %s\n", e.AddedAt.Format(time.RFC3339)))
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// --- Knowledge base tool helpers ---

// optionalBoolArg extracts an optional boolean parameter, returning
// the default if absent or not a boolean.
func optionalBoolArg(args map[string]interface{}, key string, defaultVal bool) bool {
	val, ok := args[key]
	if !ok {
		return defaultVal
	}
	b, ok := val.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

// patternRefFromFindingID extracts the pattern reference from a finding ID.
// Finding IDs follow the format "pattern-ref:file:line" or just "pattern-ref".
func patternRefFromFindingID(findingID string) string {
	parts := strings.SplitN(findingID, ":", 2)
	return parts[0]
}

// formatStats renders a slice of RuleStats as a human-readable table.
func formatStats(stats []knowledge.RuleStats) string {
	type statsJSON struct {
		PatternRef        string  `json:"pattern_ref"`
		TotalFeedback     int     `json:"total_feedback"`
		Confirmed         int     `json:"confirmed"`
		FalsePositives    int     `json:"false_positives"`
		Missed            int     `json:"missed"`
		FalsePositiveRate float64 `json:"false_positive_rate"`
		Precision         float64 `json:"precision"`
	}

	items := make([]statsJSON, len(stats))
	for i, st := range stats {
		items[i] = statsJSON{
			PatternRef:        st.PatternRef,
			TotalFeedback:     st.TotalFeedback,
			Confirmed:         st.Confirmed,
			FalsePositives:    st.FalsePositives,
			Missed:            st.Missed,
			FalsePositiveRate: st.FalsePositiveRate,
			Precision:         st.Precision,
		}
	}

	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Sprintf("error formatting stats: %v", err)
	}
	return string(data)
}
