package scan

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// TriagePriority holds a finding annotated with its learning value.
type TriagePriority struct {
	Finding  Finding
	Priority float64
	Reason   string
	Impact   int // estimated number of similar findings affected
}

// TriageConfig controls guided labeling behavior.
type TriageConfig struct {
	BucketCoverageWeight float64 // default 0.4
	UncertaintyWeight    float64 // default 0.3
	SeverityWeight       float64 // default 0.2
	DiversityWeight      float64 // default 0.1
	MinSampleThreshold   int     // default 5
}

// DefaultTriageConfig returns sensible defaults for guided triage labeling.
func DefaultTriageConfig() TriageConfig {
	return TriageConfig{
		BucketCoverageWeight: 0.4,
		UncertaintyWeight:    0.3,
		SeverityWeight:       0.2,
		DiversityWeight:      0.1,
		MinSampleThreshold:   5,
	}
}

// ComputeTriagePriorities scores all findings by learning value.
// Higher priority = labeling this finding teaches the system more.
// The input slice is NOT modified; a new sorted slice is returned.
func ComputeTriagePriorities(
	findings []Finding,
	cal *knowledge.CalibrationStore,
	cfg TriageConfig,
) []TriagePriority {
	if len(findings) == 0 {
		return nil
	}

	// Count findings per bucket for impact estimation.
	bucketCounts := make(map[knowledge.BucketKey]int)
	for _, f := range findings {
		glob := fileGlobForTriage(f.File)
		key := knowledge.NewBucketKey(f.PatternRef, glob)
		bucketCounts[key]++
	}

	priorities := make([]TriagePriority, 0, len(findings))
	for _, f := range findings {
		p := scoreFinding(f, cal, cfg, bucketCounts)
		priorities = append(priorities, p)
	}

	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i].Priority > priorities[j].Priority
	})

	return priorities
}

// scoreFinding computes a learning-value score for a single finding.
func scoreFinding(
	f Finding,
	cal *knowledge.CalibrationStore,
	cfg TriageConfig,
	bucketCounts map[knowledge.BucketKey]int,
) TriagePriority {
	var score float64
	var reason string

	// Factor 1: Bucket coverage — uncovered buckets are most valuable to label.
	glob := fileGlobForTriage(f.File)
	key := knowledge.NewBucketKey(f.PatternRef, glob)
	impact := bucketCounts[key]

	if cal != nil {
		bucket := cal.GetBucket(key)
		if !bucket.HasMinSamples(cfg.MinSampleThreshold) {
			score += cfg.BucketCoverageWeight
			reason = fmt.Sprintf("new bucket: %s", key.FileGlob())
		}
	} else {
		// No calibration store — all buckets treated as new.
		score += cfg.BucketCoverageWeight
		reason = "no calibration data"
	}

	// Factor 2: Uncertainty — findings near 0.5 confidence yield most information.
	uncertainty := 1.0 - math.Abs(f.Confidence-0.5)*2
	score += uncertainty * cfg.UncertaintyWeight

	// Factor 3: Severity — higher-severity findings have more impact when labeled.
	switch f.Severity {
	case knowledge.SeverityCritical:
		score += cfg.SeverityWeight
	case knowledge.SeverityHigh:
		score += cfg.SeverityWeight * 0.75
	case knowledge.SeverityMedium:
		score += cfg.SeverityWeight * 0.5
	case knowledge.SeverityLow:
		score += cfg.SeverityWeight * 0.25
	}

	if reason == "" {
		reason = fmt.Sprintf("uncertainty=%.2f", uncertainty)
	}

	return TriagePriority{
		Finding:  f,
		Priority: score,
		Reason:   reason,
		Impact:   impact,
	}
}

// IsColdStart returns true if more than 80% of unique finding buckets lack
// the minimum number of calibration samples. A cold start means guided
// labeling should be used to maximize coverage of new buckets.
func IsColdStart(findings []Finding, cal *knowledge.CalibrationStore, minSamples int) bool {
	if cal == nil {
		return true
	}
	seen := make(map[knowledge.BucketKey]bool)
	cold := 0
	total := 0
	for _, f := range findings {
		glob := fileGlobForTriage(f.File)
		key := knowledge.NewBucketKey(f.PatternRef, glob)
		if seen[key] {
			continue
		}
		seen[key] = true
		total++
		if !cal.GetBucket(key).HasMinSamples(minSamples) {
			cold++
		}
	}
	if total == 0 {
		return true
	}
	return float64(cold)/float64(total) > 0.8
}

// fileGlobForTriage extracts a file extension glob pattern from a file path.
// Compound extensions are preserved:
//
//	"src/orders/orders.controller.ts" → "*.controller.ts"
//	"handlers/auth.go"               → "*.go"
//	"Makefile"                       → "*"
func fileGlobForTriage(filePath string) string {
	if filePath == "" {
		return "*"
	}
	base := filepath.Base(filePath)
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return "*"
	}
	if len(parts) >= 3 {
		// Compound extension: "orders.controller.ts" → "*.controller.ts"
		return "*." + strings.Join(parts[len(parts)-2:], ".")
	}
	// Simple extension: "auth.go" → "*.go"
	return "*." + parts[len(parts)-1]
}
