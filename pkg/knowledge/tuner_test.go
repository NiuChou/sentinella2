package knowledge

import (
	"testing"
)

func testKB(patterns ...Pattern) KnowledgeBase {
	pidx, cbp, pbs := buildIndexes(patterns, nil)
	return KnowledgeBase{
		patterns:     patterns,
		patternIndex: pidx,
		patternsBySev: pbs,
		casesByPattern: cbp,
	}
}

func TestTunerNoFeedback(t *testing.T) {
	t.Parallel()

	kb := testKB(
		Pattern{ID: "auth/idor", Severity: SeverityHigh},
		Pattern{ID: "injection/sql", Severity: SeverityCritical},
	)

	tuner := NewTuner(DefaultTuneConfig())
	_, results := tuner.Tune(kb, nil)

	for _, r := range results {
		if r.Action != "unchanged" {
			t.Errorf("pattern %s: expected unchanged, got %s", r.PatternID, r.Action)
		}
	}
}

func TestTunerBelowMinFeedback(t *testing.T) {
	t.Parallel()

	kb := testKB(Pattern{ID: "auth/idor", Severity: SeverityHigh})
	stats := []RuleStats{
		{PatternRef: "auth/idor", TotalFeedback: 3, Confirmed: 1, FalsePositives: 2, FalsePositiveRate: 0.666},
	}

	tuner := NewTuner(TuneConfig{MinFeedback: 5, FPThreshold: 0.3, HighConfirmThreshold: 0.8})
	_, results := tuner.Tune(kb, stats)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "unchanged" {
		t.Errorf("expected unchanged (below min feedback), got %s", results[0].Action)
	}
}

func TestTunerDisabledHighFPRate(t *testing.T) {
	t.Parallel()

	kb := testKB(Pattern{ID: "auth/idor", Severity: SeverityHigh})
	stats := []RuleStats{
		{PatternRef: "auth/idor", TotalFeedback: 10, Confirmed: 1, FalsePositives: 9, FalsePositiveRate: 0.9},
	}

	tuner := NewTuner(DefaultTuneConfig())
	_, results := tuner.Tune(kb, stats)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "disabled" {
		t.Errorf("expected disabled, got %s", results[0].Action)
	}
	if results[0].Confidence != 0.0 {
		t.Errorf("expected 0.0 confidence for disabled, got %f", results[0].Confidence)
	}
}

func TestTunerDowngradedModerateFPRate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity Severity
		wantSev  Severity
	}{
		{"critical to high", SeverityCritical, SeverityHigh},
		{"high to medium", SeverityHigh, SeverityMedium},
		{"medium to low", SeverityMedium, SeverityLow},
		{"low stays low", SeverityLow, SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kb := testKB(Pattern{ID: "test/pattern", Severity: tt.severity})
			stats := []RuleStats{
				{PatternRef: "test/pattern", TotalFeedback: 10, Confirmed: 4, FalsePositives: 6, FalsePositiveRate: 0.6},
			}

			tuner := NewTuner(DefaultTuneConfig())
			tuned, results := tuner.Tune(kb, stats)

			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Action != "downgraded" {
				t.Errorf("expected downgraded, got %s", results[0].Action)
			}
			if results[0].OldSev != tt.severity {
				t.Errorf("expected old severity %s, got %s", tt.severity, results[0].OldSev)
			}
			if results[0].NewSev != tt.wantSev {
				t.Errorf("expected new severity %s, got %s", tt.wantSev, results[0].NewSev)
			}

			// Verify the tuned KB has the new severity.
			p, ok := tuned.PatternByID("test/pattern")
			if !ok {
				t.Fatal("pattern not found in tuned KB")
			}
			if p.Severity != tt.wantSev {
				t.Errorf("tuned pattern severity = %s, want %s", p.Severity, tt.wantSev)
			}
		})
	}
}

func TestTunerNewHint(t *testing.T) {
	t.Parallel()

	kb := testKB(Pattern{ID: "auth/csrf", Severity: SeverityMedium})
	// FP rate = 4/10 = 0.4, which is > 0.3 (default threshold) but <= 0.5.
	stats := []RuleStats{
		{PatternRef: "auth/csrf", TotalFeedback: 10, Confirmed: 6, FalsePositives: 4, FalsePositiveRate: 0.4},
	}

	tuner := NewTuner(DefaultTuneConfig())
	_, results := tuner.Tune(kb, stats)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "new_hint" {
		t.Errorf("expected new_hint, got %s", results[0].Action)
	}
	if len(results[0].NewHints) == 0 {
		t.Error("expected at least one new hint")
	}
	// Severity should not change for new_hint.
	if results[0].OldSev != results[0].NewSev {
		t.Errorf("severity should not change for new_hint: old=%s new=%s",
			results[0].OldSev, results[0].NewSev)
	}
}

func TestTunerBoosted(t *testing.T) {
	t.Parallel()

	kb := testKB(Pattern{ID: "injection/cmd", Severity: SeverityCritical})
	// Confirm rate = 9/10 = 0.9 > 0.8, FP rate = 1/10 = 0.1 < 0.3.
	stats := []RuleStats{
		{PatternRef: "injection/cmd", TotalFeedback: 10, Confirmed: 9, FalsePositives: 1, FalsePositiveRate: 0.1, Precision: 0.9},
	}

	tuner := NewTuner(DefaultTuneConfig())
	_, results := tuner.Tune(kb, stats)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "boosted" {
		t.Errorf("expected boosted, got %s", results[0].Action)
	}
	if results[0].Confidence != 1.2 {
		t.Errorf("expected 1.2 confidence, got %f", results[0].Confidence)
	}
}

func TestTunerImmutability(t *testing.T) {
	t.Parallel()

	original := testKB(Pattern{ID: "auth/idor", Severity: SeverityCritical})
	stats := []RuleStats{
		{PatternRef: "auth/idor", TotalFeedback: 10, Confirmed: 4, FalsePositives: 6, FalsePositiveRate: 0.6},
	}

	tuner := NewTuner(DefaultTuneConfig())
	tuned, _ := tuner.Tune(original, stats)

	// Original KB must remain unchanged.
	origPattern, _ := original.PatternByID("auth/idor")
	if origPattern.Severity != SeverityCritical {
		t.Errorf("original KB was mutated: severity = %s, want CRITICAL", origPattern.Severity)
	}

	// Tuned KB should have the new severity.
	tunedPattern, _ := tuned.PatternByID("auth/idor")
	if tunedPattern.Severity != SeverityHigh {
		t.Errorf("tuned KB severity = %s, want HIGH", tunedPattern.Severity)
	}
}

func TestTunerIndexRebuild(t *testing.T) {
	t.Parallel()

	kb := testKB(
		Pattern{ID: "p1", Severity: SeverityCritical},
		Pattern{ID: "p2", Severity: SeverityHigh},
	)
	// Downgrade p1 from CRITICAL to HIGH.
	stats := []RuleStats{
		{PatternRef: "p1", TotalFeedback: 10, Confirmed: 4, FalsePositives: 6, FalsePositiveRate: 0.6},
	}

	tuner := NewTuner(DefaultTuneConfig())
	tuned, _ := tuner.Tune(kb, stats)

	// After tuning, p1 should be HIGH. PatternsBySeverity should reflect this.
	highPatterns := tuned.PatternsBySeverity(SeverityHigh)
	if len(highPatterns) != 2 {
		t.Errorf("expected 2 HIGH patterns after downgrade, got %d", len(highPatterns))
	}

	critPatterns := tuned.PatternsBySeverity(SeverityCritical)
	if len(critPatterns) != 0 {
		t.Errorf("expected 0 CRITICAL patterns after downgrade, got %d", len(critPatterns))
	}
}

func TestDefaultTuneConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultTuneConfig()
	if cfg.MinFeedback != 5 {
		t.Errorf("MinFeedback = %d, want 5", cfg.MinFeedback)
	}
	if cfg.FPThreshold != 0.3 {
		t.Errorf("FPThreshold = %f, want 0.3", cfg.FPThreshold)
	}
	if cfg.HighConfirmThreshold != 0.8 {
		t.Errorf("HighConfirmThreshold = %f, want 0.8", cfg.HighConfirmThreshold)
	}
}
