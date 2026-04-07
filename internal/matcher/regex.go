// Package matcher provides deterministic pattern matching for the sentinella2
// Tier 1 scan engine. RegexMatcher compiles and caches regex patterns;
// GlobMatcher handles file path matching against glob patterns.
package matcher

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"
)

// Match represents a single regex match within file content.
type Match struct {
	Line    int    // 1-based line number of the match
	Column  int    // 1-based column offset within the line
	Text    string // the matched text
	Context string // surrounding lines for display
}

// contextLines is the number of lines shown before and after a match.
const contextLines = 2

// RegexMatcher compiles and caches regex patterns for efficient reuse.
// Safe for concurrent use.
type RegexMatcher struct {
	cache sync.Map // map[string]*regexp.Regexp
}

// NewRegexMatcher returns a new RegexMatcher with an empty cache.
func NewRegexMatcher() *RegexMatcher {
	return &RegexMatcher{}
}

// compile returns a compiled regex for the given pattern, using the cache
// to avoid recompilation. Returns an error if the pattern is invalid.
func (m *RegexMatcher) compile(pattern string) (*regexp.Regexp, error) {
	if cached, ok := m.cache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}

	// Store-or-load to handle concurrent compilation of the same pattern.
	actual, _ := m.cache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), nil
}

// Match checks if content matches the pattern and returns all match
// locations with line numbers, columns, and surrounding context.
func (m *RegexMatcher) Match(pattern string, content []byte) ([]Match, error) {
	re, err := m.compile(pattern)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(content, []byte("\n"))
	lineOffsets := buildLineOffsets(content)

	indexes := re.FindAllIndex(content, -1)
	if len(indexes) == 0 {
		return nil, nil
	}

	matches := make([]Match, 0, len(indexes))
	for _, loc := range indexes {
		line := offsetToLine(lineOffsets, loc[0])
		col := loc[0] - lineOffsets[line-1] + 1
		ctx := extractContext(lines, line)
		matches = append(matches, Match{
			Line:    line,
			Column:  col,
			Text:    string(content[loc[0]:loc[1]]),
			Context: ctx,
		})
	}

	return matches, nil
}

// MatchWithNegative checks the positive pattern but excludes matches where
// the negative pattern also matches within proximityLines of the positive
// match. This implements the "already mitigated" detection from the
// knowledge base rules.
func (m *RegexMatcher) MatchWithNegative(
	pattern, negativePattern string,
	content []byte,
	proximityLines int,
) ([]Match, error) {
	positiveMatches, err := m.Match(pattern, content)
	if err != nil {
		return nil, err
	}
	if len(positiveMatches) == 0 {
		return nil, nil
	}

	// If there is no negative pattern, return all positive matches.
	if negativePattern == "" {
		return positiveMatches, nil
	}

	negMatches, err := m.Match(negativePattern, content)
	if err != nil {
		return nil, fmt.Errorf("negative pattern error: %w", err)
	}

	// Build a set of line numbers covered by negative matches and their
	// proximity window so we can quickly check exclusion.
	negLines := buildNegativeLineSet(negMatches, proximityLines)

	filtered := make([]Match, 0, len(positiveMatches))
	for _, pm := range positiveMatches {
		if !negLines[pm.Line] {
			filtered = append(filtered, pm)
		}
	}

	return filtered, nil
}

// buildLineOffsets returns the byte offset of the start of each line.
// Index 0 corresponds to line 1.
func buildLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToLine returns the 1-based line number for the given byte offset.
func offsetToLine(lineOffsets []int, offset int) int {
	lo, hi := 0, len(lineOffsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if lineOffsets[mid] <= offset {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return lo // 1-based because lineOffsets[0] is line 1
}

// extractContext returns the surrounding lines around a 1-based line number.
func extractContext(lines [][]byte, line int) string {
	start := line - 1 - contextLines
	if start < 0 {
		start = 0
	}
	end := line - 1 + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	var buf bytes.Buffer
	for i := start; i < end; i++ {
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(lines[i])
	}
	return buf.String()
}

// buildNegativeLineSet returns a set of line numbers that fall within
// proximityLines of any negative match.
func buildNegativeLineSet(negMatches []Match, proximity int) map[int]bool {
	lines := make(map[int]bool)
	for _, nm := range negMatches {
		lo := nm.Line - proximity
		if lo < 1 {
			lo = 1
		}
		hi := nm.Line + proximity
		for l := lo; l <= hi; l++ {
			lines[l] = true
		}
	}
	return lines
}
