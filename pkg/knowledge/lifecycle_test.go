package knowledge

import (
	"testing"
)

// defaultTestConfig returns a LifecycleConfig with well-known thresholds for tests.
func defaultTestConfig() LifecycleConfig {
	return LifecycleConfig{
		PromoteToTesting: PromotionRule{
			MinScans:         5,
			MinTruePositives: 3,
		},
		PromoteToStable: PromotionRule{
			MinScans:         20,
			MinConfidence:    0.70,
			MinTruePositives: 10,
		},
		AutoDeprecate: DeprecateRule{
			MaxFPRate:  0.95,
			MinSamples: 20,
		},
	}
}

func TestLifecycle_ExperimentalToTesting(t *testing.T) {
	tests := []struct {
		name        string
		stats       RuleStats
		wantTrans   bool
		wantNewStat string
	}{
		{
			name: "meets thresholds",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 10,
				Confirmed:     5,
			},
			wantTrans:   true,
			wantNewStat: StatusTesting,
		},
		{
			name: "insufficient scans",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 3,
				Confirmed:     3,
			},
			wantTrans: false,
		},
		{
			name: "insufficient true positives",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 10,
				Confirmed:     2,
			},
			wantTrans: false,
		},
		{
			name: "exactly at threshold",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 5,
				Confirmed:     3,
			},
			wantTrans:   true,
			wantNewStat: StatusTesting,
		},
	}

	engine := NewLifecycleEngine(defaultTestConfig())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patterns := []Pattern{{ID: "P1", Status: StatusExperimental}}
			stats := []RuleStats{tc.stats}

			transitions := engine.Evaluate(patterns, stats)

			if tc.wantTrans {
				if len(transitions) != 1 {
					t.Fatalf("expected 1 transition, got %d", len(transitions))
				}
				if transitions[0].NewStatus != tc.wantNewStat {
					t.Errorf("NewStatus = %q, want %q", transitions[0].NewStatus, tc.wantNewStat)
				}
				if transitions[0].OldStatus != StatusExperimental {
					t.Errorf("OldStatus = %q, want %q", transitions[0].OldStatus, StatusExperimental)
				}
			} else {
				if len(transitions) != 0 {
					t.Fatalf("expected 0 transitions, got %d", len(transitions))
				}
			}
		})
	}
}

func TestLifecycle_TestingToStable(t *testing.T) {
	tests := []struct {
		name        string
		stats       RuleStats
		wantTrans   bool
		wantNewStat string
	}{
		{
			name: "meets all thresholds",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 25,
				Confirmed:     20,
				Precision:     0.80,
			},
			wantTrans:   true,
			wantNewStat: StatusStable,
		},
		{
			name: "insufficient scans",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 15,
				Confirmed:     12,
				Precision:     0.80,
			},
			wantTrans: false,
		},
		{
			name: "precision below threshold",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 25,
				Confirmed:     10,
				Precision:     0.65,
			},
			wantTrans: false,
		},
		{
			name: "insufficient true positives",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 25,
				Confirmed:     8,
				Precision:     0.80,
			},
			wantTrans: false,
		},
		{
			name: "exactly at threshold",
			stats: RuleStats{
				PatternRef:    "P1",
				TotalFeedback: 20,
				Confirmed:     10,
				Precision:     0.70,
			},
			wantTrans:   true,
			wantNewStat: StatusStable,
		},
	}

	engine := NewLifecycleEngine(defaultTestConfig())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patterns := []Pattern{{ID: "P1", Status: StatusTesting}}
			stats := []RuleStats{tc.stats}

			transitions := engine.Evaluate(patterns, stats)

			if tc.wantTrans {
				if len(transitions) != 1 {
					t.Fatalf("expected 1 transition, got %d", len(transitions))
				}
				if transitions[0].NewStatus != tc.wantNewStat {
					t.Errorf("NewStatus = %q, want %q", transitions[0].NewStatus, tc.wantNewStat)
				}
				if transitions[0].OldStatus != StatusTesting {
					t.Errorf("OldStatus = %q, want %q", transitions[0].OldStatus, StatusTesting)
				}
			} else {
				if len(transitions) != 0 {
					t.Fatalf("expected 0 transitions, got %d", len(transitions))
				}
			}
		})
	}
}

func TestLifecycle_AutoDeprecate(t *testing.T) {
	tests := []struct {
		name          string
		patternStatus string
		stats         RuleStats
		wantTrans     bool
	}{
		{
			name:          "experimental deprecated on high FP",
			patternStatus: StatusExperimental,
			stats: RuleStats{
				PatternRef:        "P1",
				TotalFeedback:     25,
				FalsePositiveRate: 0.96,
			},
			wantTrans: true,
		},
		{
			name:          "testing deprecated on high FP",
			patternStatus: StatusTesting,
			stats: RuleStats{
				PatternRef:        "P1",
				TotalFeedback:     25,
				FalsePositiveRate: 0.96,
			},
			wantTrans: true,
		},
		{
			name:          "stable deprecated on high FP",
			patternStatus: StatusStable,
			stats: RuleStats{
				PatternRef:        "P1",
				TotalFeedback:     25,
				FalsePositiveRate: 0.96,
			},
			wantTrans: true,
		},
		{
			name:          "insufficient samples prevents deprecation",
			patternStatus: StatusTesting,
			stats: RuleStats{
				PatternRef:        "P1",
				TotalFeedback:     10,
				FalsePositiveRate: 0.99,
			},
			wantTrans: false,
		},
		{
			name:          "FP rate at threshold not deprecated",
			patternStatus: StatusTesting,
			stats: RuleStats{
				PatternRef:        "P1",
				TotalFeedback:     25,
				FalsePositiveRate: 0.95, // not strictly greater than
			},
			wantTrans: false,
		},
	}

	engine := NewLifecycleEngine(defaultTestConfig())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patterns := []Pattern{{ID: "P1", Status: tc.patternStatus}}
			stats := []RuleStats{tc.stats}

			transitions := engine.Evaluate(patterns, stats)

			if tc.wantTrans {
				if len(transitions) != 1 {
					t.Fatalf("expected 1 transition, got %d", len(transitions))
				}
				if transitions[0].NewStatus != StatusDeprecated {
					t.Errorf("NewStatus = %q, want %q", transitions[0].NewStatus, StatusDeprecated)
				}
			} else {
				if len(transitions) != 0 {
					t.Fatalf("expected 0 transitions, got %d: %v", len(transitions), transitions)
				}
			}
		})
	}
}

func TestLifecycle_InsufficientData_NoTransition(t *testing.T) {
	engine := NewLifecycleEngine(defaultTestConfig())

	// Pattern with no matching stats.
	patterns := []Pattern{{ID: "P1", Status: StatusExperimental}}
	stats := []RuleStats{{PatternRef: "OTHER", TotalFeedback: 100, Confirmed: 50}}

	transitions := engine.Evaluate(patterns, stats)
	if len(transitions) != 0 {
		t.Fatalf("expected 0 transitions for unmatched pattern, got %d", len(transitions))
	}

	// Pattern with stats but zero feedback.
	stats2 := []RuleStats{{PatternRef: "P1", TotalFeedback: 0}}
	transitions2 := engine.Evaluate(patterns, stats2)
	if len(transitions2) != 0 {
		t.Fatalf("expected 0 transitions for zero feedback, got %d", len(transitions2))
	}
}

func TestLifecycle_DeprecatedStaysDeprecated(t *testing.T) {
	engine := NewLifecycleEngine(defaultTestConfig())

	// Even with perfect stats, deprecated patterns must not be resurrected.
	patterns := []Pattern{{ID: "P1", Status: StatusDeprecated}}
	stats := []RuleStats{{
		PatternRef:    "P1",
		TotalFeedback: 100,
		Confirmed:     100,
		Precision:     1.0,
	}}

	transitions := engine.Evaluate(patterns, stats)
	if len(transitions) != 0 {
		t.Fatalf("deprecated pattern should produce no transition, got %d: %v", len(transitions), transitions)
	}
}

func TestLifecycle_Apply_Immutability(t *testing.T) {
	engine := NewLifecycleEngine(defaultTestConfig())

	original := []Pattern{
		{ID: "P1", Status: StatusExperimental},
		{ID: "P2", Status: StatusTesting},
	}
	transitions := []Transition{
		{PatternID: "P1", OldStatus: StatusExperimental, NewStatus: StatusTesting},
	}

	result := engine.Apply(original, transitions)

	// Original must not be modified.
	if original[0].Status != StatusExperimental {
		t.Errorf("original[0].Status mutated: got %q, want %q", original[0].Status, StatusExperimental)
	}

	// Result must reflect the transition.
	if result[0].Status != StatusTesting {
		t.Errorf("result[0].Status = %q, want %q", result[0].Status, StatusTesting)
	}

	// Untransitioned pattern must be unchanged.
	if result[1].Status != StatusTesting {
		t.Errorf("result[1].Status = %q, want %q", result[1].Status, StatusTesting)
	}

	// Result must be a distinct slice (different backing array).
	result[1].Status = StatusStable
	if original[1].Status == StatusStable {
		t.Error("modifying result affected original — not immutable")
	}
}

func TestPattern_EffectiveConfidenceWeight(t *testing.T) {
	tests := []struct {
		name             string
		status           string
		confidenceWeight float64
		want             float64
	}{
		{"experimental default", StatusExperimental, 0, 0.5},
		{"testing default", StatusTesting, 0, 0.75},
		{"stable default", StatusStable, 0, 1.0},
		{"deprecated default", StatusDeprecated, 0, 0.25},
		{"empty status defaults to stable", "", 0, 1.0},
		{"unknown status defaults to 1.0", "unknown", 0, 1.0},
		{"explicit weight overrides status", StatusExperimental, 0.9, 0.9},
		{"explicit weight overrides deprecated", StatusDeprecated, 1.5, 1.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Pattern{Status: tc.status, ConfidenceWeight: tc.confidenceWeight}
			got := p.EffectiveConfidenceWeight()
			if got != tc.want {
				t.Errorf("EffectiveConfidenceWeight() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPattern_IsVisibleByDefault(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{StatusExperimental, false},
		{StatusTesting, true},
		{StatusStable, true},
		{StatusDeprecated, false},
		{"", true}, // empty defaults to stable-like visibility
		{"unknown", true},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			p := Pattern{Status: tc.status}
			got := p.IsVisibleByDefault()
			if got != tc.want {
				t.Errorf("IsVisibleByDefault() = %v, want %v for status %q", got, tc.want, tc.status)
			}
		})
	}
}

func TestPattern_CanBlockCI(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{StatusStable, true},
		{"", true}, // empty defaults to stable behavior
		{StatusExperimental, false},
		{StatusTesting, false},
		{StatusDeprecated, false},
		{"unknown", false},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			p := Pattern{Status: tc.status}
			got := p.CanBlockCI()
			if got != tc.want {
				t.Errorf("CanBlockCI() = %v, want %v for status %q", got, tc.want, tc.status)
			}
		})
	}
}
