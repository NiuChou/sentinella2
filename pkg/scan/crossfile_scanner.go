package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/perseworks/sentinella2/internal/matcher"
	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// CrossFileScanner implements Scanner using cross-file correlation analysis
// (Tier 2). Unlike RuleScanner, which examines each file in isolation,
// CrossFileScanner collects pattern matches across the entire codebase,
// groups them, and applies relational assertions to detect systemic issues.
type CrossFileScanner struct {
	opts         options
	regexMatcher *matcher.RegexMatcher
	globMatcher  *matcher.GlobMatcher
}

// NewCrossFileScanner creates a new CrossFileScanner with the given options.
func NewCrossFileScanner(opts ...Option) *CrossFileScanner {
	o := defaultOptions()
	for _, fn := range opts {
		fn(&o)
	}
	return &CrossFileScanner{
		opts:         o,
		regexMatcher: matcher.NewRegexMatcher(),
		globMatcher:  matcher.NewGlobMatcher(),
	}
}

// crossFileMatch holds a single regex match with its file context.
type crossFileMatch struct {
	file    string
	line    int
	text    string
	context string
	group   string // derived from GroupBy strategy
}

// indexedFile holds a file's relative path and content for the file index.
type indexedFile struct {
	relPath string
	content []byte
}

// Scan walks targetDir and applies cross-file rules from the knowledge base.
func (s *CrossFileScanner) Scan(ctx context.Context, targetDir string) (Result, error) {
	start := time.Now()

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolving target directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return Result{}, fmt.Errorf("accessing target directory: %w", err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("target path %q is not a directory", absDir)
	}

	// Filter to patterns with cross-file rules within the tier limit.
	patterns := s.crossFilePatterns()
	if len(patterns) == 0 {
		return NewResult(nil, absDir, 0, 0, time.Since(start)), nil
	}

	// Collect unique CollectFrom globs across all patterns for pre-filtering.
	collectGlobs := s.mergeCollectGlobs(patterns)

	// Build file index: only read files matching at least one CollectFrom glob.
	fileIndex := s.buildFileIndex(ctx, absDir, collectGlobs)

	var findings []Finding
	for _, pat := range patterns {
		select {
		case <-ctx.Done():
			return NewResult(findings, absDir, len(patterns), len(fileIndex), time.Since(start)), nil
		default:
		}

		cf := pat.Detection.CrossFile
		matches := s.collectMatches(cf, fileIndex)
		grouped := groupMatches(matches)
		patFindings := s.evaluateAssertion(pat, cf, grouped)
		findings = append(findings, patFindings...)
	}

	return NewResult(findings, absDir, len(patterns), len(fileIndex), time.Since(start)), nil
}

// crossFilePatterns returns patterns that have cross-file rules and are within
// the tier limit.
func (s *CrossFileScanner) crossFilePatterns() []knowledge.Pattern {
	var out []knowledge.Pattern
	for _, p := range s.opts.kb.PatternsForTier(s.opts.maxTier) {
		if p.Detection.CrossFile != nil && p.Detection.CrossFile.Collect != "" {
			out = append(out, p)
		}
	}
	return out
}

// mergeCollectGlobs deduplicates CollectFrom globs across all patterns.
func (s *CrossFileScanner) mergeCollectGlobs(patterns []knowledge.Pattern) []string {
	seen := make(map[string]bool)
	var globs []string
	for _, p := range patterns {
		for _, g := range p.Detection.CrossFile.CollectFrom {
			if !seen[g] {
				seen[g] = true
				globs = append(globs, g)
			}
		}
	}
	return globs
}

// buildFileIndex walks the directory and reads files matching at least one of
// the given globs. Only matched files are loaded to minimize memory usage.
func (s *CrossFileScanner) buildFileIndex(
	ctx context.Context,
	absDir string,
	globs []string,
) map[string]indexedFile {
	index := make(map[string]indexedFile)

	_ = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "dist" || base == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		relPath, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return nil
		}

		// Pre-filter: only read files matching at least one CollectFrom glob.
		if !s.globMatcher.MatchPath(relPath, globs) {
			return nil
		}

		content, readErr := readFileBounded(path)
		if readErr != nil {
			return nil
		}

		index[relPath] = indexedFile{relPath: relPath, content: content}
		return nil
	})

	return index
}

// collectMatches finds all matches for a cross-file rule across the file index.
func (s *CrossFileScanner) collectMatches(
	cf *knowledge.CrossFileRule,
	fileIndex map[string]indexedFile,
) []crossFileMatch {
	re, err := regexp.Compile(cf.Collect)
	if err != nil {
		return nil
	}

	var matches []crossFileMatch
	for relPath, f := range fileIndex {
		if !s.globMatcher.MatchPath(relPath, cf.CollectFrom) {
			continue
		}

		lines := strings.Split(string(f.content), "\n")
		for lineNum, line := range lines {
			if re.MatchString(line) {
				matches = append(matches, crossFileMatch{
					file:    relPath,
					line:    lineNum + 1,
					text:    strings.TrimSpace(line),
					context: extractMatchContext(lines, lineNum, 2),
					group:   deriveGroup(relPath, cf.GroupBy),
				})
			}
		}
	}

	return matches
}

// groupMatches partitions matches by their group key.
func groupMatches(matches []crossFileMatch) map[string][]crossFileMatch {
	groups := make(map[string][]crossFileMatch)
	for _, m := range matches {
		groups[m.group] = append(groups[m.group], m)
	}
	return groups
}

// deriveGroup computes the group key for a file path based on the groupBy
// strategy.
func deriveGroup(relPath string, groupBy string) string {
	switch groupBy {
	case "top_directory":
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 2)
		if len(parts) > 1 {
			return parts[0]
		}
		return "_root"
	case "none", "":
		return "_all"
	default:
		return "_all"
	}
}

// evaluateAssertion dispatches to the correct assertion strategy.
func (s *CrossFileScanner) evaluateAssertion(
	pat knowledge.Pattern,
	cf *knowledge.CrossFileRule,
	grouped map[string][]crossFileMatch,
) []Finding {
	switch cf.AssertType {
	case "duplication":
		return assertDuplication(pat, grouped)
	case "consistency":
		return assertConsistency(pat, cf, grouped)
	case "completeness":
		return assertCompleteness(pat, cf, grouped)
	default:
		return nil
	}
}
