package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// defaultValueExtractPattern is the fallback regex for extracting values in
// consistency assertions when no ValueExtract is defined on the rule.
var defaultValueExtractPattern = regexp.MustCompile(`[:=]\s*(\d+|['"][^'"]+['"])`)

// assertDuplication flags when multiple groups have matches for the same
// pattern. The lexicographically first group is treated as the "canonical"
// implementation; all others are flagged as duplicates.
func assertDuplication(
	pat knowledge.Pattern,
	grouped map[string][]crossFileMatch,
) []Finding {
	if len(grouped) <= 1 {
		return nil
	}

	// Sort group keys for deterministic output.
	keys := sortedGroupKeys(grouped)

	// Report one finding per group beyond the canonical (first sorted).
	var findings []Finding
	for _, group := range keys[1:] {
		matches := grouped[group]
		if len(matches) == 0 {
			continue
		}

		m := matches[0]
		msg := fmt.Sprintf(
			"%s — found %d independent implementations across %d groups (%s)",
			pat.Description, countTotalMatches(grouped), len(grouped), group,
		)

		findings = append(findings, Finding{
			RuleID:      pat.ID,
			PatternRef:  pat.ID,
			Severity:    pat.Severity,
			File:        m.file,
			Line:        m.line,
			Message:     msg,
			MatchedText: m.text,
			Context:     buildCrossFileContext(grouped),
			FixHint:     pat.Fix.Abstract,
			Confidence:  0.7 * pat.EffectiveConfidenceWeight(),
		})
	}

	return findings
}

// assertConsistency flags when extracted values differ across groups or files.
// It uses the CrossFileRule.ValueExtract regex if defined, falling back to
// the defaultValueExtractPattern.
func assertConsistency(
	pat knowledge.Pattern,
	cf *knowledge.CrossFileRule,
	grouped map[string][]crossFileMatch,
) []Finding {
	re := defaultValueExtractPattern
	if cf.ValueExtract != "" {
		compiled, err := regexp.Compile(cf.ValueExtract)
		if err == nil {
			re = compiled
		}
	}

	// Extract values from matched lines, keyed by unique value string.
	allValues := make(map[string][]crossFileMatch)
	for _, matches := range grouped {
		for _, m := range matches {
			submatch := re.FindStringSubmatch(m.text)
			if len(submatch) > 1 {
				val := strings.Trim(submatch[1], `'"`)
				allValues[val] = append(allValues[val], m)
			}
		}
	}

	if len(allValues) <= 1 {
		return nil // All values are consistent
	}

	// Sort value keys for deterministic output.
	valueKeys := make([]string, 0, len(allValues))
	for k := range allValues {
		valueKeys = append(valueKeys, k)
	}
	sort.Strings(valueKeys)

	// Use the first match of the first sorted value as the finding anchor.
	firstMatch := allValues[valueKeys[0]][0]

	msg := fmt.Sprintf(
		"%s — found inconsistent values: [%s]",
		pat.Description, strings.Join(valueKeys, ", "),
	)

	return []Finding{{
		RuleID:      pat.ID,
		PatternRef:  pat.ID,
		Severity:    pat.Severity,
		File:        firstMatch.file,
		Line:        firstMatch.line,
		Message:     msg,
		MatchedText: firstMatch.text,
		Context:     buildCrossFileContext(grouped),
		FixHint:     pat.Fix.Abstract,
		Confidence:  0.65 * pat.EffectiveConfidenceWeight(),
	}}
}

// assertCompleteness flags when a required chain of patterns is incomplete
// within a group. Uses word-boundary matching to avoid false matches against
// substrings of unrelated identifiers (e.g., "refreshInterval" matching
// "refresh").
func assertCompleteness(
	pat knowledge.Pattern,
	cf *knowledge.CrossFileRule,
	grouped map[string][]crossFileMatch,
) []Finding {
	requiredParts := parseChainRequirements(cf.Assert)
	if len(requiredParts) == 0 {
		return nil
	}

	// Sort group keys for deterministic output.
	keys := sortedGroupKeys(grouped)

	var findings []Finding
	for _, group := range keys {
		matches := grouped[group]
		combinedText := buildCombinedText(matches)
		missing := findMissingChainParts(combinedText, requiredParts)
		if len(missing) == 0 {
			continue // Chain is complete in this group
		}

		firstMatch := crossFileMatch{file: "unknown", line: 0}
		if len(matches) > 0 {
			firstMatch = matches[0]
		}

		msg := fmt.Sprintf(
			"%s — incomplete chain in %q: missing [%s]",
			pat.Description, group, strings.Join(missing, ", "),
		)

		findings = append(findings, Finding{
			RuleID:      pat.ID,
			PatternRef:  pat.ID,
			Severity:    pat.Severity,
			File:        firstMatch.file,
			Line:        firstMatch.line,
			Message:     msg,
			MatchedText: firstMatch.text,
			Context:     buildCrossFileContext(grouped),
			FixHint:     pat.Fix.Abstract,
			Confidence:  0.6 * pat.EffectiveConfidenceWeight(),
		})
	}

	return findings
}

// parseChainRequirements extracts required chain parts from an assert string.
// Format: "chain_has_all_of: part1,part2_or_part3"
func parseChainRequirements(assert string) []string {
	parts := strings.SplitN(assert, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	raw := strings.TrimSpace(parts[1])
	return strings.Split(raw, ",")
}

// findMissingChainParts checks which required parts are absent from the
// combined text. Uses word-boundary regex (\b) to avoid false matches
// against substrings of unrelated identifiers. "X_or_Y" is treated as
// alternatives where either X or Y satisfies the requirement.
func findMissingChainParts(text string, required []string) []string {
	var missing []string
	for _, req := range required {
		req = strings.TrimSpace(req)
		alternatives := strings.Split(req, "_or_")
		found := false
		for _, alt := range alternatives {
			alt = strings.TrimSpace(alt)
			pattern := `(?i)\b` + regexp.QuoteMeta(alt) + `\b`
			re, err := regexp.Compile(pattern)
			if err != nil {
				// Fallback to substring match if regex fails.
				if strings.Contains(text, alt) {
					found = true
					break
				}
				continue
			}
			if re.MatchString(text) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, req)
		}
	}
	return missing
}

// --- Helpers ---

// buildCombinedText concatenates all match text and context for chain analysis.
func buildCombinedText(matches []crossFileMatch) string {
	var b strings.Builder
	for _, m := range matches {
		b.WriteString(m.text)
		b.WriteByte(' ')
		b.WriteString(m.context)
		b.WriteByte('\n')
	}
	return b.String()
}

// sortedGroupKeys returns the keys of a group map in sorted order.
func sortedGroupKeys(grouped map[string][]crossFileMatch) []string {
	keys := make([]string, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractMatchContext returns ±n lines around the given line index.
func extractMatchContext(lines []string, lineIdx int, n int) string {
	start := lineIdx - n
	if start < 0 {
		start = 0
	}
	end := lineIdx + n + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

// buildCrossFileContext creates a deterministic summary of all locations
// across groups.
func buildCrossFileContext(grouped map[string][]crossFileMatch) string {
	keys := sortedGroupKeys(grouped)
	var b strings.Builder
	b.WriteString("Cross-file matches:\n")
	for _, group := range keys {
		fmt.Fprintf(&b, "  [%s]:\n", group)
		for _, m := range grouped[group] {
			fmt.Fprintf(&b, "    %s:%d — %s\n", m.file, m.line, truncate(m.text, 80))
		}
	}
	return b.String()
}

// countTotalMatches returns the total number of matches across all groups.
func countTotalMatches(grouped map[string][]crossFileMatch) int {
	total := 0
	for _, matches := range grouped {
		total += len(matches)
	}
	return total
}

// truncate shortens a string to maxLen, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
