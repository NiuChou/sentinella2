package scan

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/perseworks/sentinella2/internal/matcher"
	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// proximityLines is the number of lines around a positive match within
// which a negative pattern match counts as a mitigation.
const proximityLines = 5

// maxFileSize is the largest file the scanner will read (1 MB). Files
// larger than this are skipped to avoid excessive memory use.
const maxFileSize = 1 << 20

// RuleScanner implements Scanner using deterministic regex/glob matching
// (Tier 1). It walks the target directory, applies per-language rules
// from the knowledge base, and collects findings into an immutable Result.
type RuleScanner struct {
	opts         options
	regexMatcher *matcher.RegexMatcher
	globMatcher  *matcher.GlobMatcher
}

// New creates a new RuleScanner with the given options applied over defaults.
func New(opts ...Option) *RuleScanner {
	o := defaultOptions()
	for _, fn := range opts {
		fn(&o)
	}
	return &RuleScanner{
		opts:         o,
		regexMatcher: matcher.NewRegexMatcher(),
		globMatcher:  matcher.NewGlobMatcher(),
	}
}

// Scan walks targetDir and applies Tier 1 rules from the knowledge base.
// It respects context cancellation and returns partial results on cancel.
func (s *RuleScanner) Scan(ctx context.Context, targetDir string) (Result, error) {
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

	patterns := s.opts.kb.PatternsForTier(s.opts.maxTier)

	var findings []Finding
	filesScanned := 0

	walkErr := filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		// Check cancellation at each directory/file.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if s.shouldSkipDir(path, absDir) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks to prevent following them outside the scan root.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		relPath, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return nil
		}

		if !s.shouldScanFile(relPath) {
			return nil
		}

		lang := detectLanguage(path)
		if lang == "" {
			return nil
		}

		content, readErr := readFileBounded(path)
		if readErr != nil {
			return nil // skip unreadable files
		}

		fileFindings := s.scanFile(ctx, relPath, lang, content, patterns)
		findings = append(findings, fileFindings...)
		filesScanned++

		return nil
	})

	if walkErr != nil && walkErr != context.Canceled {
		return Result{}, fmt.Errorf("walking target directory: %w", walkErr)
	}

	// Post-processing: cross-scanner correlation adjustment.
	if s.opts.correlationCfg != nil && len(findings) > 0 {
		findings = AdjustByCorrelation(findings, *s.opts.correlationCfg)
	}

	return NewResult(findings, absDir, len(patterns), filesScanned, time.Since(start)), nil
}

// shouldSkipDir returns true if the directory should be excluded from walking.
func (s *RuleScanner) shouldSkipDir(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	// Check exclude globs against the directory path with a trailing slash.
	dirPath := rel + "/"
	return s.globMatcher.MatchPath(dirPath, s.opts.excludeGlobs)
}

// shouldScanFile checks include/exclude globs and the changedOnly list.
func (s *RuleScanner) shouldScanFile(relPath string) bool {
	// If changedOnly is set, the file must be in the list.
	if len(s.opts.changedOnly) > 0 {
		found := false
		for _, cf := range s.opts.changedOnly {
			if cf == relPath || cf == filepath.ToSlash(relPath) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check exclude globs.
	if s.globMatcher.MatchPath(relPath, s.opts.excludeGlobs) {
		return false
	}

	// If include globs are set, the file must match at least one.
	if len(s.opts.includeGlobs) > 0 {
		return s.globMatcher.MatchPath(relPath, s.opts.includeGlobs)
	}

	return true
}

// scanFile applies all applicable patterns to a single file and returns
// the findings. It does not mutate any shared state.
func (s *RuleScanner) scanFile(
	ctx context.Context,
	relPath string,
	lang string,
	content []byte,
	patterns []knowledge.Pattern,
) []Finding {
	var findings []Finding

	for _, pat := range patterns {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		rule, ok := pat.Detection.Rules[lang]
		if !ok {
			continue
		}

		// Check if the file matches the rule's context glob.
		if rule.Context != "" {
			contextGlob := extractGlob(rule.Context)
			if contextGlob != "" && !s.globMatcher.MatchPath(relPath, []string{contextGlob}) {
				continue
			}
		}

		// Memory check: skip this pattern if memory declares it not applicable.
		if s.opts.memories != nil {
			if memorySkipsPattern(s.opts.memories.ForScanner(pat.ID), pat.ID) {
				continue
			}
		}

		matches, err := s.regexMatcher.MatchWithNegative(
			rule.Pattern, rule.NegativePattern, content, proximityLines,
		)
		if err != nil {
			continue // skip patterns with invalid regex
		}

		for _, m := range matches {
			conf := 0.5 // cold start default
			if s.opts.calibration != nil {
				conf = s.opts.calibration.ConfidenceFor(pat.ID, relPath)
			}
			// Apply lifecycle weight (experimental=0.5, testing=0.75, stable=1.0)
			conf *= pat.EffectiveConfidenceWeight()
			if conf > 1.0 {
				conf = 1.0
			}

			findings = append(findings, Finding{
				RuleID:      pat.ID,
				PatternRef:  pat.ID,
				Severity:    pat.Severity,
				File:        relPath,
				Line:        m.Line,
				Column:      m.Column,
				Message:     pat.Description,
				MatchedText: m.Text,
				Context:     m.Context,
				FixHint:     pat.Fix.Abstract,
				Confidence:  conf,
			})
		}
	}

	return findings
}

// detectLanguage maps file extensions to language keys used in pattern rules.
// Returns an empty string for unrecognized extensions.
func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	// Check special filenames first.
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."):
		return "dockerfile"
	case base == "makefile":
		return "makefile"
	case base == "caddyfile":
		return "caddy"
	}

	languages := map[string]string{
		".go":    "go",
		".ts":    "typescript",
		".tsx":   "typescript",
		".js":    "javascript",
		".jsx":   "javascript",
		".py":    "python",
		".rb":    "ruby",
		".rs":    "rust",
		".java":  "java",
		".kt":    "kotlin",
		".swift": "swift",
		".c":     "c",
		".h":     "c",
		".cpp":   "cpp",
		".hpp":   "cpp",
		".cs":    "csharp",
		".php":   "php",
		".yaml":  "yaml",
		".yml":   "yaml",
		".json":  "json",
		".toml":  "toml",
		".sh":    "shell",
		".bash":  "shell",
		".zsh":   "shell",
		".sql":   "sql",
		".tf":    "terraform",
		".hcl":   "hcl",
		".conf":  "conf",
	}

	return languages[ext]
}

// extractGlob strips descriptive text from a context field, returning
// only the glob pattern portion. Context fields in the knowledge base
// may contain annotations like "**/*.go — HTTP handlers".
func extractGlob(contextField string) string {
	// Split on common separators between glob and description.
	for _, sep := range []string{" — ", " - ", " — "} {
		if idx := strings.Index(contextField, sep); idx > 0 {
			return strings.TrimSpace(contextField[:idx])
		}
	}
	return strings.TrimSpace(contextField)
}

// memorySkipsPattern returns true if any memory declares the given pattern
// should be skipped. A scanner-scoped memory with Scanner matching patternID
// is treated as a not-applicable declaration for that pattern on the matched files.
func memorySkipsPattern(mems []knowledge.Memory, patternID string) bool {
	for _, m := range mems {
		if m.Scope == knowledge.ScopeScanner && m.Scanner == patternID {
			return true
		}
	}
	return false
}

// readFileBounded reads a file up to maxFileSize bytes. Returns an error
// if the file cannot be read or exceeds the size limit.
func readFileBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("file %q exceeds max size (%d bytes)", path, maxFileSize)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("skipping symlink %q", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxFileSize))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	return data, nil
}
