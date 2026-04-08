package scan

import (
	"testing"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// openTestCalibrationStore creates a CalibrationStore backed by a temp file.
// The file path is computed but the file itself does not pre-exist so that
// OpenCalibrationStore initialises a fresh empty store.
func openTestCalibrationStore(t *testing.T) *knowledge.CalibrationStore {
	t.Helper()
	path := t.TempDir() + "/calibration.json"
	cs, err := knowledge.OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("open calibration store: %v", err)
	}
	return cs
}

// recordVerdicts records n confirmed verdicts for a pattern+glob bucket.
func recordVerdicts(cs *knowledge.CalibrationStore, patternRef, fileGlob string, n int) {
	for i := 0; i < n; i++ {
		cs.RecordVerdict(patternRef, fileGlob, knowledge.VerdictConfirmed)
	}
}

func TestComputeTriagePriorities_Empty(t *testing.T) {
	result := ComputeTriagePriorities(nil, nil, DefaultTriageConfig())
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}

	result = ComputeTriagePriorities([]Finding{}, nil, DefaultTriageConfig())
	if result != nil {
		t.Errorf("expected nil for empty slice, got %v", result)
	}
}

func TestComputeTriagePriorities_NilCalibration(t *testing.T) {
	findings := []Finding{
		{PatternRef: "sql-injection", File: "handlers/db.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
		{PatternRef: "xss", File: "views/template.html", Severity: knowledge.SeverityMedium, Confidence: 0.7},
	}

	result := ComputeTriagePriorities(findings, nil, DefaultTriageConfig())

	if len(result) != 2 {
		t.Fatalf("expected 2 priorities, got %d", len(result))
	}

	// All buckets should be treated as new (bucket coverage weight applied).
	cfg := DefaultTriageConfig()
	for _, p := range result {
		if p.Priority < cfg.BucketCoverageWeight {
			t.Errorf("finding %s: expected priority >= %.2f, got %.4f",
				p.Finding.PatternRef, cfg.BucketCoverageWeight, p.Priority)
		}
	}
}

func TestComputeTriagePriorities_ColdStart(t *testing.T) {
	// Cold start: all buckets have zero samples — bucket coverage should dominate.
	cal := openTestCalibrationStore(t)
	cfg := DefaultTriageConfig()

	findings := []Finding{
		{PatternRef: "sql-injection", File: "handlers/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
		{PatternRef: "xss", File: "views/page.html", Severity: knowledge.SeverityMedium, Confidence: 0.5},
		{PatternRef: "path-traversal", File: "upload/handler.go", Severity: knowledge.SeverityCritical, Confidence: 0.5},
	}

	result := ComputeTriagePriorities(findings, cal, cfg)

	if len(result) != 3 {
		t.Fatalf("expected 3 priorities, got %d", len(result))
	}

	// All findings get bucket coverage weight since all buckets are new.
	for _, p := range result {
		if p.Priority < cfg.BucketCoverageWeight {
			t.Errorf("%s: expected priority >= %.2f (cold bucket), got %.4f",
				p.Finding.PatternRef, cfg.BucketCoverageWeight, p.Priority)
		}
	}

	// Results should be sorted descending by priority.
	for i := 1; i < len(result); i++ {
		if result[i].Priority > result[i-1].Priority {
			t.Errorf("results not sorted: result[%d].Priority=%.4f > result[%d].Priority=%.4f",
				i, result[i].Priority, i-1, result[i-1].Priority)
		}
	}
}

func TestComputeTriagePriorities_HotStart(t *testing.T) {
	// Hot start: all buckets have plenty of samples — uncertainty should dominate.
	cal := openTestCalibrationStore(t)
	cfg := DefaultTriageConfig()

	// Add enough samples to each bucket so they are "warm".
	warmFindings := []Finding{
		{PatternRef: "sql-injection", File: "handlers/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
		{PatternRef: "xss", File: "views/page.html", Severity: knowledge.SeverityMedium, Confidence: 0.8},
	}
	for _, f := range warmFindings {
		glob := fileGlobForTriage(f.File)
		recordVerdicts(cal, f.PatternRef, glob, cfg.MinSampleThreshold)
	}

	// High uncertainty finding vs low uncertainty finding.
	findings := []Finding{
		{PatternRef: "sql-injection", File: "handlers/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},  // high uncertainty
		{PatternRef: "xss", File: "views/page.html", Severity: knowledge.SeverityMedium, Confidence: 0.95},           // low uncertainty
	}

	result := ComputeTriagePriorities(findings, cal, cfg)

	if len(result) != 2 {
		t.Fatalf("expected 2 priorities, got %d", len(result))
	}

	// The high-uncertainty finding should rank higher.
	if result[0].Finding.PatternRef != "sql-injection" {
		t.Errorf("expected sql-injection first (high uncertainty), got %s", result[0].Finding.PatternRef)
	}
}

func TestComputeTriagePriorities_SeverityFactor(t *testing.T) {
	// Equal confidence and coverage — CRITICAL should outrank LOW.
	cal := openTestCalibrationStore(t)
	cfg := DefaultTriageConfig()

	// Pre-warm both buckets so coverage doesn't dominate.
	recordVerdicts(cal, "pattern-a", "*.go", cfg.MinSampleThreshold)
	recordVerdicts(cal, "pattern-b", "*.go", cfg.MinSampleThreshold)

	findings := []Finding{
		{PatternRef: "pattern-a", File: "code/low.go", Severity: knowledge.SeverityLow, Confidence: 0.5},
		{PatternRef: "pattern-b", File: "code/critical.go", Severity: knowledge.SeverityCritical, Confidence: 0.5},
	}

	result := ComputeTriagePriorities(findings, cal, cfg)

	if len(result) != 2 {
		t.Fatalf("expected 2 priorities, got %d", len(result))
	}

	if result[0].Finding.Severity != knowledge.SeverityCritical {
		t.Errorf("expected CRITICAL severity to rank first, got %s", result[0].Finding.Severity)
	}
}

func TestComputeTriagePriorities_ImpactCount(t *testing.T) {
	// Multiple findings with the same bucket — impact should reflect group size.
	findings := []Finding{
		{PatternRef: "sql-injection", File: "a/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
		{PatternRef: "sql-injection", File: "b/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
		{PatternRef: "sql-injection", File: "c/query.go", Severity: knowledge.SeverityHigh, Confidence: 0.5},
	}

	result := ComputeTriagePriorities(findings, nil, DefaultTriageConfig())

	for _, p := range result {
		if p.Impact != 3 {
			t.Errorf("expected impact=3 for shared bucket, got %d", p.Impact)
		}
	}
}

func TestIsColdStart_NilCal(t *testing.T) {
	findings := []Finding{
		{PatternRef: "sql-injection", File: "query.go", Confidence: 0.5},
	}
	if !IsColdStart(findings, nil, 5) {
		t.Error("expected cold start when cal is nil")
	}
}

func TestIsColdStart_AllCold(t *testing.T) {
	cal := openTestCalibrationStore(t)
	findings := []Finding{
		{PatternRef: "a", File: "foo.go", Confidence: 0.5},
		{PatternRef: "b", File: "bar.go", Confidence: 0.5},
		{PatternRef: "c", File: "baz.go", Confidence: 0.5},
	}
	if !IsColdStart(findings, cal, 5) {
		t.Error("expected cold start when no calibration data")
	}
}

func TestIsColdStart_MostlyCovered(t *testing.T) {
	// Warm up 4 out of 5 buckets → 20% cold → not cold start.
	cal := openTestCalibrationStore(t)
	minSamples := 5
	patterns := []string{"a", "b", "c", "d"}
	for _, p := range patterns {
		recordVerdicts(cal, p, "*.go", minSamples)
	}

	findings := []Finding{
		{PatternRef: "a", File: "a.go"},
		{PatternRef: "b", File: "b.go"},
		{PatternRef: "c", File: "c.go"},
		{PatternRef: "d", File: "d.go"},
		{PatternRef: "e", File: "e.go"}, // cold
	}

	if IsColdStart(findings, cal, minSamples) {
		t.Error("expected NOT cold start when 80% of buckets are covered")
	}
}

func TestIsColdStart_EmptyFindings(t *testing.T) {
	cal := openTestCalibrationStore(t)
	if !IsColdStart(nil, cal, 5) {
		t.Error("expected cold start for empty findings")
	}
}

func TestFileGlobForTriage(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "simple go extension",
			filePath: "handlers/auth.go",
			want:     "*.go",
		},
		{
			name:     "compound controller extension",
			filePath: "src/orders/orders.controller.ts",
			want:     "*.controller.ts",
		},
		{
			name:     "compound service extension",
			filePath: "src/users/users.service.ts",
			want:     "*.service.ts",
		},
		{
			name:     "compound spec extension",
			filePath: "src/users/users.spec.ts",
			want:     "*.spec.ts",
		},
		{
			name:     "simple html",
			filePath: "views/index.html",
			want:     "*.html",
		},
		{
			name:     "no extension",
			filePath: "Makefile",
			want:     "*",
		},
		{
			name:     "empty path",
			filePath: "",
			want:     "*",
		},
		{
			name:     "nested path simple ext",
			filePath: "a/b/c/file.py",
			want:     "*.py",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fileGlobForTriage(tc.filePath)
			if got != tc.want {
				t.Errorf("fileGlobForTriage(%q) = %q, want %q", tc.filePath, got, tc.want)
			}
		})
	}
}
