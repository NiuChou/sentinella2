package scan

import (
	"testing"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

func TestGrade(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
		want       ConfidenceGrade
	}{
		{name: "zero confidence is Suspect", confidence: 0.0, want: GradeSuspect},
		{name: "below 0.3 is Suspect", confidence: 0.29, want: GradeSuspect},
		{name: "exactly 0.3 is Likely", confidence: 0.3, want: GradeLikely},
		{name: "mid-range is Likely", confidence: 0.5, want: GradeLikely},
		{name: "exactly 0.7 is Likely", confidence: 0.7, want: GradeLikely},
		{name: "just above 0.7 is Confirmed", confidence: 0.701, want: GradeConfirmed},
		{name: "full confidence is Confirmed", confidence: 1.0, want: GradeConfirmed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{Confidence: tc.confidence}
			got := f.Grade()
			if got != tc.want {
				t.Errorf("Grade() = %q, want %q (confidence=%.3f)", got, tc.want, tc.confidence)
			}
		})
	}
}

func TestGradeFindings(t *testing.T) {
	findings := []Finding{
		{RuleID: "r1", Severity: knowledge.SeverityHigh, Confidence: 0.9},  // Confirmed
		{RuleID: "r2", Severity: knowledge.SeverityMedium, Confidence: 0.5}, // Likely
		{RuleID: "r3", Severity: knowledge.SeverityLow, Confidence: 0.1},    // Suspect
		{RuleID: "r4", Severity: knowledge.SeverityCritical, Confidence: 0.8}, // Confirmed
		{RuleID: "r5", Severity: knowledge.SeverityMedium, Confidence: 0.3},   // Likely
	}

	result := GradeFindings(findings)

	if len(result.All) != 5 {
		t.Errorf("All: got %d, want 5", len(result.All))
	}
	if len(result.Confirmed) != 2 {
		t.Errorf("Confirmed: got %d, want 2", len(result.Confirmed))
	}
	if len(result.Likely) != 2 {
		t.Errorf("Likely: got %d, want 2", len(result.Likely))
	}
	if len(result.Suspect) != 1 {
		t.Errorf("Suspect: got %d, want 1", len(result.Suspect))
	}

	// Verify correct findings in each bucket.
	confirmedIDs := map[string]bool{"r1": true, "r4": true}
	for _, f := range result.Confirmed {
		if !confirmedIDs[f.RuleID] {
			t.Errorf("unexpected finding %q in Confirmed", f.RuleID)
		}
	}

	likelyIDs := map[string]bool{"r2": true, "r5": true}
	for _, f := range result.Likely {
		if !likelyIDs[f.RuleID] {
			t.Errorf("unexpected finding %q in Likely", f.RuleID)
		}
	}

	if result.Suspect[0].RuleID != "r3" {
		t.Errorf("Suspect[0]: got %q, want r3", result.Suspect[0].RuleID)
	}
}

func TestGradeFindings_Empty(t *testing.T) {
	result := GradeFindings(nil)

	if len(result.All) != 0 {
		t.Errorf("All: got %d, want 0", len(result.All))
	}
	if result.Confirmed != nil {
		t.Errorf("Confirmed: got non-nil, want nil")
	}
	if result.Likely != nil {
		t.Errorf("Likely: got non-nil, want nil")
	}
	if result.Suspect != nil {
		t.Errorf("Suspect: got non-nil, want nil")
	}
}

func TestGradeFindings_ImmutableAll(t *testing.T) {
	original := []Finding{
		{RuleID: "r1", Confidence: 0.8},
	}
	result := GradeFindings(original)

	// Mutating the original should not affect result.All.
	original[0].RuleID = "mutated"
	if result.All[0].RuleID == "mutated" {
		t.Error("GradeFindings result.All shares memory with input; expected deep copy")
	}
}
