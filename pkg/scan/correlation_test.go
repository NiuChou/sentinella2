package scan

import (
	"math"
	"testing"
)

// approxEqual checks floating-point equality within a small epsilon.
func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestCorrelation_MultiScannerBoost(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		{PatternRef: "pat-A", File: "main.go", Confidence: 0.6},
		{PatternRef: "pat-B", File: "main.go", Confidence: 0.5},
		{PatternRef: "pat-C", File: "main.go", Confidence: 0.4},
	}

	got := AdjustByCorrelation(findings, cfg)

	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}
	for i, f := range got {
		want := math.Min(findings[i].Confidence*cfg.MultiScannerBoost, cfg.MaxConfidence)
		if !approxEqual(f.Confidence, want) {
			t.Errorf("finding[%d]: want confidence %.4f, got %.4f", i, want, f.Confidence)
		}
	}
}

func TestCorrelation_LoneFinderPenalty(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		{PatternRef: "pat-A", File: "auth.go", Confidence: 0.3},
	}

	got := AdjustByCorrelation(findings, cfg)

	want := 0.3 * cfg.LoneFinderPenalty
	if !approxEqual(got[0].Confidence, want) {
		t.Errorf("want confidence %.4f, got %.4f", want, got[0].Confidence)
	}
}

func TestCorrelation_LoneFinderHighConfidence(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		{PatternRef: "pat-A", File: "auth.go", Confidence: 0.8},
	}

	got := AdjustByCorrelation(findings, cfg)

	// Confidence >= 0.5 with a single pattern: no adjustment.
	if !approxEqual(got[0].Confidence, 0.8) {
		t.Errorf("want confidence 0.8 (unchanged), got %.4f", got[0].Confidence)
	}
}

func TestCorrelation_TwoPatterns(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		{PatternRef: "pat-A", File: "db.go", Confidence: 0.4},
		{PatternRef: "pat-B", File: "db.go", Confidence: 0.4},
	}

	got := AdjustByCorrelation(findings, cfg)

	// 2 distinct patterns: below MinScannersForBoost (3), no boost, no penalty.
	for i, f := range got {
		if !approxEqual(f.Confidence, findings[i].Confidence) {
			t.Errorf("finding[%d]: want confidence %.4f unchanged, got %.4f",
				i, findings[i].Confidence, f.Confidence)
		}
	}
}

func TestCorrelation_MaxConfidenceClamp(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	// 0.9 × 1.3 = 1.17 → must be clamped to 0.99
	findings := []Finding{
		{PatternRef: "pat-A", File: "net.go", Confidence: 0.9},
		{PatternRef: "pat-B", File: "net.go", Confidence: 0.9},
		{PatternRef: "pat-C", File: "net.go", Confidence: 0.9},
	}

	got := AdjustByCorrelation(findings, cfg)

	for i, f := range got {
		if f.Confidence > cfg.MaxConfidence {
			t.Errorf("finding[%d]: confidence %.4f exceeds MaxConfidence %.4f",
				i, f.Confidence, cfg.MaxConfidence)
		}
		if !approxEqual(f.Confidence, cfg.MaxConfidence) {
			t.Errorf("finding[%d]: want %.4f (clamped), got %.4f",
				i, cfg.MaxConfidence, f.Confidence)
		}
	}
}

func TestCorrelation_EmptyInput(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	got := AdjustByCorrelation(nil, cfg)
	if got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}

	got = AdjustByCorrelation([]Finding{}, cfg)
	if got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestCorrelation_Immutability(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	original := []Finding{
		{PatternRef: "pat-A", File: "api.go", Confidence: 0.4},
		{PatternRef: "pat-B", File: "api.go", Confidence: 0.4},
		{PatternRef: "pat-C", File: "api.go", Confidence: 0.4},
	}
	// Snapshot original confidences before calling.
	snapshot := make([]float64, len(original))
	for i, f := range original {
		snapshot[i] = f.Confidence
	}

	_ = AdjustByCorrelation(original, cfg)

	// Verify original slice was not mutated.
	for i, f := range original {
		if !approxEqual(f.Confidence, snapshot[i]) {
			t.Errorf("original[%d] was mutated: want %.4f, got %.4f",
				i, snapshot[i], f.Confidence)
		}
	}
}

func TestCorrelation_MixedFiles(t *testing.T) {
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		// "a.go": 3 distinct patterns → boost
		{PatternRef: "pat-A", File: "a.go", Confidence: 0.5},
		{PatternRef: "pat-B", File: "a.go", Confidence: 0.5},
		{PatternRef: "pat-C", File: "a.go", Confidence: 0.5},
		// "b.go": 1 pattern, low confidence → penalty
		{PatternRef: "pat-X", File: "b.go", Confidence: 0.2},
		// "c.go": 2 patterns → no change
		{PatternRef: "pat-M", File: "c.go", Confidence: 0.6},
		{PatternRef: "pat-N", File: "c.go", Confidence: 0.6},
	}

	got := AdjustByCorrelation(findings, cfg)

	tests := []struct {
		idx  int
		want float64
		desc string
	}{
		{0, math.Min(0.5*cfg.MultiScannerBoost, cfg.MaxConfidence), "a.go pat-A boosted"},
		{1, math.Min(0.5*cfg.MultiScannerBoost, cfg.MaxConfidence), "a.go pat-B boosted"},
		{2, math.Min(0.5*cfg.MultiScannerBoost, cfg.MaxConfidence), "a.go pat-C boosted"},
		{3, 0.2 * cfg.LoneFinderPenalty, "b.go lone finder penalized"},
		{4, 0.6, "c.go pat-M unchanged"},
		{5, 0.6, "c.go pat-N unchanged"},
	}

	for _, tc := range tests {
		if !approxEqual(got[tc.idx].Confidence, tc.want) {
			t.Errorf("%s: want %.4f, got %.4f", tc.desc, tc.want, got[tc.idx].Confidence)
		}
	}
}

func TestCorrelation_CustomConfig(t *testing.T) {
	cfg := CorrelationConfig{
		MultiScannerBoost:   1.5,
		MinScannersForBoost: 2, // lower threshold
		LoneFinderPenalty:   0.4,
		MaxConfidence:       0.95,
	}

	findings := []Finding{
		// 2 distinct patterns → should boost with custom config
		{PatternRef: "pat-A", File: "svc.go", Confidence: 0.5},
		{PatternRef: "pat-B", File: "svc.go", Confidence: 0.5},
		// 1 pattern, low confidence → penalized
		{PatternRef: "pat-X", File: "util.go", Confidence: 0.3},
	}

	got := AdjustByCorrelation(findings, cfg)

	wantBoosted := math.Min(0.5*1.5, 0.95)
	if !approxEqual(got[0].Confidence, wantBoosted) {
		t.Errorf("svc.go pat-A: want %.4f, got %.4f", wantBoosted, got[0].Confidence)
	}
	if !approxEqual(got[1].Confidence, wantBoosted) {
		t.Errorf("svc.go pat-B: want %.4f, got %.4f", wantBoosted, got[1].Confidence)
	}

	wantPenalized := 0.3 * 0.4
	if !approxEqual(got[2].Confidence, wantPenalized) {
		t.Errorf("util.go pat-X: want %.4f, got %.4f", wantPenalized, got[2].Confidence)
	}
}

func TestCorrelation_DuplicatePatternSameFile(t *testing.T) {
	// Same PatternRef appearing twice in one file counts as ONE distinct pattern.
	cfg := DefaultCorrelationConfig()
	findings := []Finding{
		{PatternRef: "pat-A", File: "dup.go", Confidence: 0.3},
		{PatternRef: "pat-A", File: "dup.go", Confidence: 0.3}, // same pattern, different line
	}

	got := AdjustByCorrelation(findings, cfg)

	// distinctCount == 1, confidence < 0.5 → penalty
	want := 0.3 * cfg.LoneFinderPenalty
	for i, f := range got {
		if !approxEqual(f.Confidence, want) {
			t.Errorf("finding[%d]: want %.4f (penalized), got %.4f", i, want, f.Confidence)
		}
	}
}
