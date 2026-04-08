package knowledge

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// FPCluster represents a group of false positive findings sharing common traits.
type FPCluster struct {
	PatternRef  string  // e.g. "auth-flow/missing-auth-check"
	FilePattern string  // e.g. "*.controller.ts"
	FPCount     int     // number of false positives in this cluster
	TotalCount  int     // total findings for this (pattern, filePattern) combo
	FPRate      float64 // FPCount / TotalCount
	CommonTrait string  // human-readable description of the pattern
}

// SuggestedActionType classifies what kind of action to take.
type SuggestedActionType string

const (
	SuggestMemory    SuggestedActionType = "memory"
	SuggestException SuggestedActionType = "exception"
	SuggestRuleFix   SuggestedActionType = "rule_fix"
)

// SuggestedAction is a recommendation based on mined patterns.
type SuggestedAction struct {
	Type        SuggestedActionType
	Cluster     FPCluster
	Description string // human-readable suggestion text
	MemoryText  string // if Type==SuggestMemory, the memory to add
	ConfigYAML  string // if Type==SuggestException, the YAML snippet
}

// MinerConfig controls the pattern mining thresholds.
type MinerConfig struct {
	MinFPRate  float64 // minimum FP rate to consider (default: 0.8)
	MinSamples int     // minimum samples in a cluster (default: 5)
}

// DefaultMinerConfig returns sensible defaults.
func DefaultMinerConfig() MinerConfig {
	return MinerConfig{
		MinFPRate:  0.8,
		MinSamples: 5,
	}
}

// MinerResult holds the output of pattern mining.
type MinerResult struct {
	Clusters      []FPCluster
	Suggested     []SuggestedAction
	TotalAnalyzed int
}

// Miner analyzes feedback data to discover patterns and suggest improvements.
// It is stateless; all state flows through Mine() arguments.
type Miner struct {
	config MinerConfig
}

// NewMiner creates a Miner with the given configuration.
func NewMiner(cfg MinerConfig) *Miner {
	return &Miner{config: cfg}
}

// Mine analyzes feedback entries and discovers false positive patterns.
// It returns clusters and suggested actions. Input entries are not modified.
func (m *Miner) Mine(entries []FeedbackEntry) MinerResult {
	if len(entries) == 0 {
		return MinerResult{}
	}

	fpEntries := filterFalsePositives(entries)

	// Group all entries by (PatternRef, filePattern) for total count.
	totalCounts := buildClusterCounts(entries)

	// Group FP entries by (PatternRef, filePattern).
	fpCounts := buildClusterCounts(fpEntries)

	clusters := m.buildClusters(fpCounts, totalCounts)
	suggested := m.buildSuggestions(clusters)

	return MinerResult{
		Clusters:      clusters,
		Suggested:     suggested,
		TotalAnalyzed: len(entries),
	}
}

// --- internal types ---

// clusterKey uniquely identifies a (PatternRef, filePattern) pair.
type clusterKey struct {
	patternRef  string
	filePattern string
}

// --- mining helpers ---

// filterFalsePositives returns only entries with verdict == false_positive.
func filterFalsePositives(entries []FeedbackEntry) []FeedbackEntry {
	result := make([]FeedbackEntry, 0, len(entries))
	for _, e := range entries {
		if e.Verdict == VerdictFalsePositive {
			result = append(result, e)
		}
	}
	return result
}

// buildClusterCounts groups entries by (PatternRef, filePattern) and counts them.
func buildClusterCounts(entries []FeedbackEntry) map[clusterKey]int {
	counts := make(map[clusterKey]int)
	for _, e := range entries {
		key := clusterKey{
			patternRef:  e.PatternRef,
			filePattern: extractFilePattern(e.File),
		}
		counts[key]++
	}
	return counts
}

// buildClusters creates FPCluster values for (pattern, filePattern) pairs that
// meet the MinFPRate and MinSamples thresholds. Returned slice is sorted
// deterministically by descending FP rate, then by pattern ref.
func (m *Miner) buildClusters(fpCounts, totalCounts map[clusterKey]int) []FPCluster {
	var clusters []FPCluster

	for key, fpCount := range fpCounts {
		total := totalCounts[key]
		if total == 0 {
			total = fpCount
		}

		if fpCount < m.config.MinSamples {
			continue
		}

		fpRate := float64(fpCount) / float64(total)
		if fpRate < m.config.MinFPRate {
			continue
		}

		cluster := FPCluster{
			PatternRef:  key.patternRef,
			FilePattern: key.filePattern,
			FPCount:     fpCount,
			TotalCount:  total,
			FPRate:      fpRate,
			CommonTrait: buildCommonTrait(key.patternRef, key.filePattern, fpRate),
		}
		clusters = append(clusters, cluster)
	}

	// Sort deterministically: descending FP rate, then ascending pattern ref.
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].FPRate != clusters[j].FPRate {
			return clusters[i].FPRate > clusters[j].FPRate
		}
		if clusters[i].PatternRef != clusters[j].PatternRef {
			return clusters[i].PatternRef < clusters[j].PatternRef
		}
		return clusters[i].FilePattern < clusters[j].FilePattern
	})

	return clusters
}

// buildSuggestions generates SuggestedAction recommendations for each cluster.
// Very high FP rate (>95%) → SuggestException + SuggestMemory.
// High FP rate (>=80%) → SuggestMemory only.
func (m *Miner) buildSuggestions(clusters []FPCluster) []SuggestedAction {
	suggestions := make([]SuggestedAction, 0, len(clusters))

	for _, c := range clusters {
		if c.FPRate > 0.95 {
			// Very high FP: suggest both an exception config and a memory note.
			suggestions = append(suggestions, SuggestedAction{
				Type:        SuggestException,
				Cluster:     c,
				Description: buildExceptionDescription(c),
				ConfigYAML:  buildExceptionYAML(c),
			})
			suggestions = append(suggestions, SuggestedAction{
				Type:        SuggestMemory,
				Cluster:     c,
				Description: buildMemoryDescription(c),
				MemoryText:  buildMemoryText(c),
			})
		} else {
			suggestions = append(suggestions, SuggestedAction{
				Type:        SuggestMemory,
				Cluster:     c,
				Description: buildMemoryDescription(c),
				MemoryText:  buildMemoryText(c),
			})
		}
	}

	return suggestions
}

// extractFilePattern returns a glob pattern from a file path.
// Compound extensions (e.g., .controller.ts, .service.ts, .spec.ts) are
// preserved when the basename contains multiple dots.
//
//	"src/orders/orders.controller.ts" → "*.controller.ts"
//	"src/db/schema.sql"               → "*.sql"
//	"handlers/auth.go"                → "*.go"
func extractFilePattern(filePath string) string {
	if filePath == "" {
		return "*"
	}

	base := filepath.Base(filePath)

	// Find all dot positions in basename.
	dotPositions := findDotPositions(base)
	if len(dotPositions) == 0 {
		return "*"
	}

	if len(dotPositions) >= 2 {
		// Use the second-to-last dot to capture compound extension.
		// e.g. "orders.controller.ts" → second-to-last dot at "controller"
		secondLast := dotPositions[len(dotPositions)-2]
		return "*" + base[secondLast:]
	}

	// Single dot: use simple extension.
	return "*" + base[dotPositions[0]:]
}

// findDotPositions returns the byte indices of all '.' characters in s.
func findDotPositions(s string) []int {
	var positions []int
	for i, ch := range s {
		if ch == '.' {
			positions = append(positions, i)
		}
	}
	return positions
}

// buildCommonTrait produces a human-readable description for a cluster.
func buildCommonTrait(patternRef, filePattern string, fpRate float64) string {
	return fmt.Sprintf("%s findings in %s files (%.0f%% FP rate)",
		patternRef, filePattern, fpRate*100)
}

// buildMemoryDescription produces a human-readable description for a memory suggestion.
func buildMemoryDescription(c FPCluster) string {
	return fmt.Sprintf("Add memory note: %s findings in %s are likely false positives (%.0f%% rate, %d/%d samples)",
		c.PatternRef, c.FilePattern, c.FPRate*100, c.FPCount, c.TotalCount)
}

// buildMemoryText produces the memory note text to store.
func buildMemoryText(c FPCluster) string {
	return fmt.Sprintf("%s findings in %s files are usually false positives (%.0f%% FP rate observed across %d samples)",
		c.PatternRef, c.FilePattern, c.FPRate*100, c.FPCount)
}

// buildExceptionDescription produces a human-readable description for an exception suggestion.
func buildExceptionDescription(c FPCluster) string {
	return fmt.Sprintf("Add exception rule: exclude %s from %s checks (%.0f%% FP rate, very high confidence)",
		c.FilePattern, c.PatternRef, c.FPRate*100)
}

// buildExceptionYAML produces the YAML config snippet for an exception rule.
func buildExceptionYAML(c FPCluster) string {
	// Derive a short name from the file pattern: "*.controller.ts" → "controller-ts"
	shortName := strings.TrimPrefix(c.FilePattern, "*.")
	shortName = strings.ReplaceAll(shortName, ".", "-")

	return fmt.Sprintf(`exceptions:
  - pattern: %q
    file_glob: %q
    reason: "Auto-detected: %.0f%% false positive rate across %d samples"
`,
		c.PatternRef,
		c.FilePattern,
		c.FPRate*100,
		c.FPCount,
	)
}
