package matcher

import (
	"path/filepath"
	"strings"
)

// GlobMatcher matches file paths against glob patterns.
// It supports standard filepath.Match patterns plus recursive "**/" prefix
// matching that checks any directory depth.
type GlobMatcher struct{}

// NewGlobMatcher returns a new GlobMatcher.
func NewGlobMatcher() *GlobMatcher {
	return &GlobMatcher{}
}

// MatchPath reports whether the given path matches any of the glob patterns.
// Patterns use filepath.Match syntax with an extension: a leading "**/"
// matches any number of directories (e.g., "**/*.go" matches "a/b/c.go").
// An empty patterns slice returns false.
func (m *GlobMatcher) MatchPath(path string, patterns []string) bool {
	// Normalize path separators for consistent matching.
	normalized := filepath.ToSlash(path)

	for _, pattern := range patterns {
		if matchSingle(normalized, filepath.ToSlash(pattern)) {
			return true
		}
	}
	return false
}

// matchSingle checks a single normalized path against a single normalized
// glob pattern, handling the "**/" recursive prefix.
func matchSingle(path, pattern string) bool {
	// Handle "**/" prefix by trying the suffix against every directory
	// depth of the path.
	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:]
		// Try matching suffix against the full path and every sub-path.
		if matchGlob(path, suffix) {
			return true
		}
		for i := 0; i < len(path); i++ {
			if path[i] == '/' {
				if matchGlob(path[i+1:], suffix) {
					return true
				}
			}
		}
		return false
	}

	return matchGlob(path, pattern)
}

// matchGlob wraps filepath.Match, returning false on pattern syntax errors
// rather than propagating them. It also handles brace expansion for
// patterns like "*.{ts,tsx,js,jsx}".
func matchGlob(path, pattern string) bool {
	// Handle brace expansion: "*.{ts,tsx}" -> try "*.ts" and "*.tsx".
	if idx := strings.Index(pattern, "{"); idx >= 0 {
		end := strings.Index(pattern[idx:], "}")
		if end > 0 {
			prefix := pattern[:idx]
			suffix := pattern[idx+end+1:]
			alternatives := strings.Split(pattern[idx+1:idx+end], ",")
			for _, alt := range alternatives {
				expanded := prefix + alt + suffix
				if matchGlob(path, expanded) {
					return true
				}
			}
			return false
		}
	}

	matched, _ := filepath.Match(pattern, path)
	if matched {
		return true
	}

	// Also try matching against just the filename for patterns without
	// directory separators.
	if !strings.Contains(pattern, "/") {
		base := filepath.Base(path)
		matched, _ = filepath.Match(pattern, base)
		return matched
	}

	return false
}
