package scan

import (
	"math"
)

// CorrelationConfig controls cross-scanner confidence adjustment.
type CorrelationConfig struct {
	// MultiScannerBoost is the multiplier when 3+ scanners flag the same file.
	// Default: 1.3
	MultiScannerBoost float64

	// MinScannersForBoost is the minimum number of distinct patterns required
	// to trigger the boost. Default: 3
	MinScannersForBoost int

	// LoneFinderPenalty is the multiplier when only 1 scanner flags a file
	// and that scanner has low confidence (< 0.5) for the file context.
	// Default: 0.6
	LoneFinderPenalty float64

	// MaxConfidence is the upper bound after correlation adjustment.
	// Default: 0.99
	MaxConfidence float64
}

// DefaultCorrelationConfig returns sensible defaults inspired by SpamAssassin's
// 3+3 rule: corroboration from multiple independent pattern matches raises
// confidence, while lone low-confidence findings are penalized.
func DefaultCorrelationConfig() CorrelationConfig {
	return CorrelationConfig{
		MultiScannerBoost:   1.3,
		MinScannersForBoost: 3,
		LoneFinderPenalty:   0.6,
		MaxConfidence:       0.99,
	}
}

// AdjustByCorrelation returns a NEW slice of findings with confidence values
// adjusted based on cross-scanner correlation. The input slice is NOT modified.
//
// Logic:
//   - Group findings by file
//   - Count distinct PatternRef values per file
//   - If 3+ distinct patterns flag the same file → boost all findings' confidence × 1.3
//   - If only 1 pattern flags a file AND that pattern's confidence < 0.5 → penalty × 0.6
//   - Clamp confidence to [0, MaxConfidence]
func AdjustByCorrelation(findings []Finding, cfg CorrelationConfig) []Finding {
	if len(findings) == 0 {
		return nil
	}

	// Deep copy to preserve immutability of the input slice.
	result := make([]Finding, len(findings))
	copy(result, findings)

	// Group by file → set of distinct PatternRefs.
	filePatterns := make(map[string]map[string]bool, len(result))
	for _, f := range result {
		if filePatterns[f.File] == nil {
			filePatterns[f.File] = make(map[string]bool)
		}
		filePatterns[f.File][f.PatternRef] = true
	}

	// Adjust confidence per finding based on its file's pattern count.
	for i, f := range result {
		patterns := filePatterns[f.File]
		distinctCount := len(patterns)

		switch {
		case distinctCount >= cfg.MinScannersForBoost:
			// Multi-scanner corroboration → boost, then clamp to MaxConfidence.
			result[i].Confidence = math.Min(f.Confidence*cfg.MultiScannerBoost, cfg.MaxConfidence)
		case distinctCount == 1 && f.Confidence < 0.5:
			// Lone finder with low confidence → apply penalty.
			result[i].Confidence = f.Confidence * cfg.LoneFinderPenalty
		// else: keep original confidence unchanged.
		}
	}

	return result
}
