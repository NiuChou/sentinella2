package knowledge

import (
	"testing"
	"time"
)

// makeEntries builds a slice of FeedbackEntry values for testing.
func makeEntries(patternRef string, file string, verdict Verdict, count int) []FeedbackEntry {
	entries := make([]FeedbackEntry, count)
	for i := range entries {
		entries[i] = FeedbackEntry{
			FindingID:  "id",
			PatternRef: patternRef,
			File:       file,
			Verdict:    verdict,
			Timestamp:  time.Now(),
		}
	}
	return entries
}

// seedWildcardBucket adds a wildcard bucket with the given alpha/beta directly.
func seedWildcardBucket(t *testing.T, cs *CalibrationStore, patternRef string, alpha, beta int) {
	t.Helper()
	key := NewBucketKey(patternRef, "*")
	cs.mu.Lock()
	cs.data.Buckets[key] = BetaBucket{Alpha: alpha, Beta: beta, LastUpdate: time.Now().UTC()}
	cs.mu.Unlock()
}

// seedBucket adds a named bucket with the given alpha/beta directly.
func seedBucket(t *testing.T, cs *CalibrationStore, patternRef, glob string, alpha, beta int) {
	t.Helper()
	key := NewBucketKey(patternRef, glob)
	cs.mu.Lock()
	cs.data.Buckets[key] = BetaBucket{Alpha: alpha, Beta: beta, LastUpdate: time.Now().UTC()}
	cs.mu.Unlock()
}

func TestDetectSplits_BasicDivergence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		parentAlpha   int
		parentBeta    int
		childFile     string
		childVerdict  Verdict
		childCount    int
		threshold     float64
		wantSplitGlob string
	}{
		{
			name:        "high-confidence parent, low-confidence child",
			parentAlpha: 8, parentBeta: 2, // parent conf = 0.8
			childFile: "src/orders.controller.ts", childVerdict: VerdictFalsePositive, childCount: 5,
			// child: 0/5 → conf=0.0, divergence = |0.8-0.0|/0.8 = 1.0 > 0.3
			threshold:     0.3,
			wantSplitGlob: "*.controller.ts",
		},
		{
			name:        "low-confidence parent, high-confidence child",
			parentAlpha: 2, parentBeta: 8, // parent conf = 0.2
			childFile: "handlers/auth.go", childVerdict: VerdictConfirmed, childCount: 5,
			// child: 5/5 → conf=1.0, divergence = |0.2-1.0|/0.2 = 4.0 > 0.3
			threshold:     0.3,
			wantSplitGlob: "*.go",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := openTempCalibration(t)
			seedWildcardBucket(t, cs, "auth/check", tc.parentAlpha, tc.parentBeta)

			entries := makeEntries("auth/check", tc.childFile, tc.childVerdict, tc.childCount)
			splits := cs.DetectSplits(entries, tc.threshold)

			if len(splits) == 0 {
				t.Fatal("expected at least one split, got none")
			}
			if splits[0].ChildKey.FileGlob() != tc.wantSplitGlob {
				t.Errorf("child glob: got %q, want %q", splits[0].ChildKey.FileGlob(), tc.wantSplitGlob)
			}
			if splits[0].Divergence <= tc.threshold {
				t.Errorf("divergence %.4f should exceed threshold %.4f", splits[0].Divergence, tc.threshold)
			}
		})
	}
}

func TestDetectSplits_BelowThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		parentAlpha int
		parentBeta  int
		childAlpha  int
		childBeta   int
		threshold   float64
	}{
		{
			name:        "small divergence below threshold",
			parentAlpha: 5, parentBeta: 5, // parent conf = 0.5
			childAlpha: 3, childBeta: 3, // child conf = 0.5, divergence = 0.0
			threshold: 0.3,
		},
		{
			name:        "divergence well below threshold not included",
			parentAlpha: 5, parentBeta: 5, // parent conf = 0.5
			childAlpha: 4, childBeta: 6, // child conf = 0.4, divergence = |0.5-0.4|/0.5 = 0.2
			threshold: 0.3, // divergence 0.2 < threshold 0.3 → no split
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := openTempCalibration(t)
			seedWildcardBucket(t, cs, "auth/check", tc.parentAlpha, tc.parentBeta)

			// Build entries for child
			var entries []FeedbackEntry
			for i := 0; i < tc.childAlpha; i++ {
				entries = append(entries, makeEntries("auth/check", "src/foo.go", VerdictConfirmed, 1)...)
			}
			for i := 0; i < tc.childBeta; i++ {
				entries = append(entries, makeEntries("auth/check", "src/foo.go", VerdictFalsePositive, 1)...)
			}

			splits := cs.DetectSplits(entries, tc.threshold)
			if len(splits) != 0 {
				t.Errorf("expected no splits, got %d", len(splits))
			}
		})
	}
}

func TestDetectSplits_InsufficientSamples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		parentAlpha  int
		parentBeta   int
		childCount   int // entries for child extension
		threshold    float64
		wantNoSplits bool
	}{
		{
			name:         "child group below minSampleThreshold",
			parentAlpha:  8, parentBeta: 2,
			childCount:   4, // below minSampleThreshold=5
			threshold:    0.3,
			wantNoSplits: true,
		},
		{
			name:         "child group exactly at threshold is included",
			parentAlpha:  8, parentBeta: 2,
			childCount:   5, // equal to minSampleThreshold=5
			threshold:    0.3,
			wantNoSplits: false, // 5 FP entries → conf=0.0, divergence > 0.3
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := openTempCalibration(t)
			seedWildcardBucket(t, cs, "auth/check", tc.parentAlpha, tc.parentBeta)

			entries := makeEntries("auth/check", "src/foo.controller.ts", VerdictFalsePositive, tc.childCount)
			splits := cs.DetectSplits(entries, tc.threshold)

			if tc.wantNoSplits && len(splits) != 0 {
				t.Errorf("expected no splits, got %d", len(splits))
			}
			if !tc.wantNoSplits && len(splits) == 0 {
				t.Error("expected at least one split, got none")
			}
		})
	}
}

func TestDetectSplits_ExistingChildBucket(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	// Parent wildcard bucket
	seedWildcardBucket(t, cs, "auth/check", 8, 2)
	// Child bucket already exists — should be skipped
	seedBucket(t, cs, "auth/check", "*.controller.ts", 3, 7)

	// Entries for *.controller.ts: all FP → would normally trigger split
	entries := makeEntries("auth/check", "src/orders.controller.ts", VerdictFalsePositive, 5)
	splits := cs.DetectSplits(entries, 0.3)

	if len(splits) != 0 {
		t.Errorf("expected no splits when child bucket already exists, got %d", len(splits))
	}
}

func TestDetectSplits_NoWildcard(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	// Only an exact bucket, no wildcard
	seedBucket(t, cs, "auth/check", "*.go", 8, 2)

	entries := makeEntries("auth/check", "src/foo.go", VerdictFalsePositive, 5)
	splits := cs.DetectSplits(entries, 0.3)

	if len(splits) != 0 {
		t.Errorf("expected no splits without wildcard bucket, got %d", len(splits))
	}
}

func TestDetectSplits_SortedByDivergence(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	// Two patterns, each with a wildcard bucket
	seedWildcardBucket(t, cs, "auth/check", 8, 2)   // conf=0.8
	seedWildcardBucket(t, cs, "crypto/weak", 5, 5)  // conf=0.5

	var entries []FeedbackEntry
	// auth/check: *.go → all FP → conf=0.0, divergence = 0.8/0.8 = 1.0
	entries = append(entries, makeEntries("auth/check", "src/foo.go", VerdictFalsePositive, 5)...)
	// crypto/weak: *.ts → all confirmed → conf=1.0, divergence = |0.5-1.0|/0.5 = 1.0
	entries = append(entries, makeEntries("crypto/weak", "src/foo.ts", VerdictConfirmed, 5)...)

	splits := cs.DetectSplits(entries, 0.3)
	if len(splits) < 2 {
		t.Fatalf("expected 2 splits, got %d", len(splits))
	}
	for i := 1; i < len(splits); i++ {
		if splits[i-1].Divergence < splits[i].Divergence {
			t.Errorf("splits not sorted by descending divergence: [%d]=%.4f < [%d]=%.4f",
				i-1, splits[i-1].Divergence, i, splits[i].Divergence)
		}
	}
}

func TestApplySplit_Basic(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	seedWildcardBucket(t, cs, "auth/check", 8, 2) // α=8, β=2

	// 3 confirmed entries for *.go
	entries := makeEntries("auth/check", "src/foo.go", VerdictConfirmed, 3)

	split := SplitResult{
		ParentKey: NewBucketKey("auth/check", "*"),
		ChildKey:  NewBucketKey("auth/check", "*.go"),
	}

	if err := cs.ApplySplit(split, entries); err != nil {
		t.Fatalf("ApplySplit: %v", err)
	}

	// Child bucket created with α=3, β=0
	child := cs.GetBucket(NewBucketKey("auth/check", "*.go"))
	if child.Alpha != 3 {
		t.Errorf("child Alpha: got %d, want 3", child.Alpha)
	}
	if child.Beta != 0 {
		t.Errorf("child Beta: got %d, want 0", child.Beta)
	}

	// Parent adjusted: α=8-3=5, β=2-0=2
	parent := cs.GetBucket(NewBucketKey("auth/check", "*"))
	if parent.Alpha != 5 {
		t.Errorf("parent Alpha: got %d, want 5", parent.Alpha)
	}
	if parent.Beta != 2 {
		t.Errorf("parent Beta: got %d, want 2", parent.Beta)
	}
}

func TestApplySplit_ParentMinimum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		parentAlpha  int
		parentBeta   int
		childAlpha   int
		childBeta    int
		wantParentA  int
		wantParentB  int
	}{
		{
			name:        "alpha clamped to 1",
			parentAlpha: 2, parentBeta: 5,
			childAlpha: 3, childBeta: 2, // would make parent α = 2-3 = -1 → clamp to 1
			wantParentA: 1, wantParentB: 3,
		},
		{
			name:        "beta clamped to 1",
			parentAlpha: 5, parentBeta: 2,
			childAlpha: 2, childBeta: 3, // would make parent β = 2-3 = -1 → clamp to 1
			wantParentA: 3, wantParentB: 1,
		},
		{
			name:        "both clamped to 1",
			parentAlpha: 1, parentBeta: 1,
			childAlpha: 5, childBeta: 5, // both go negative → both clamp to 1
			wantParentA: 1, wantParentB: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := openTempCalibration(t)
			seedWildcardBucket(t, cs, "pat/x", tc.parentAlpha, tc.parentBeta)

			var entries []FeedbackEntry
			for i := 0; i < tc.childAlpha; i++ {
				entries = append(entries, makeEntries("pat/x", "src/foo.go", VerdictConfirmed, 1)...)
			}
			for i := 0; i < tc.childBeta; i++ {
				entries = append(entries, makeEntries("pat/x", "src/foo.go", VerdictFalsePositive, 1)...)
			}

			split := SplitResult{
				ParentKey: NewBucketKey("pat/x", "*"),
				ChildKey:  NewBucketKey("pat/x", "*.go"),
			}

			if err := cs.ApplySplit(split, entries); err != nil {
				t.Fatalf("ApplySplit: %v", err)
			}

			parent := cs.GetBucket(NewBucketKey("pat/x", "*"))
			if parent.Alpha != tc.wantParentA {
				t.Errorf("parent Alpha: got %d, want %d", parent.Alpha, tc.wantParentA)
			}
			if parent.Beta != tc.wantParentB {
				t.Errorf("parent Beta: got %d, want %d", parent.Beta, tc.wantParentB)
			}
		})
	}
}

func TestApplySplit_MissingParent(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	// No parent bucket seeded

	split := SplitResult{
		ParentKey: NewBucketKey("auth/check", "*"),
		ChildKey:  NewBucketKey("auth/check", "*.go"),
	}
	entries := makeEntries("auth/check", "src/foo.go", VerdictConfirmed, 3)

	err := cs.ApplySplit(split, entries)
	if err == nil {
		t.Fatal("expected error for missing parent bucket, got nil")
	}
}

func TestApplySplit_NoFeedbackData(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	seedWildcardBucket(t, cs, "auth/check", 8, 2)

	split := SplitResult{
		ParentKey: NewBucketKey("auth/check", "*"),
		ChildKey:  NewBucketKey("auth/check", "*.go"),
	}
	// Entries for a different pattern — no data for auth/check/*.go
	entries := makeEntries("other/pat", "src/foo.go", VerdictConfirmed, 3)

	err := cs.ApplySplit(split, entries)
	if err == nil {
		t.Fatal("expected error for no feedback data, got nil")
	}
}
