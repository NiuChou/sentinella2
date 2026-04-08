package knowledge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// openTempCalibration creates a CalibrationStore in a temp directory with no
// built-in priors loaded.
func openTempCalibration(t *testing.T) *CalibrationStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "calibration.json")
	cs, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("OpenCalibrationStore: %v", err)
	}
	return cs
}

func TestCalibrationStore_OpenCreate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "calibration.json")

	cs, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("OpenCalibrationStore: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil store")
	}

	// File must exist on disk after open.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("calibration.json not created: %v", err)
	}

	// File must be valid JSON with correct version.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read calibration.json: %v", err)
	}
	var cf calibrationFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("parse calibration.json: %v", err)
	}
	if cf.Version != calibrationFileVersion {
		t.Errorf("version: got %d, want %d", cf.Version, calibrationFileVersion)
	}
}

func TestCalibrationStore_OpenCreateMissingDir(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "sub", "calibration.json")

	cs, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("OpenCalibrationStore with missing parent dir: %v", err)
	}
	if cs == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestCalibrationStore_OpenEmptyPath(t *testing.T) {
	t.Parallel()

	_, err := OpenCalibrationStore("", nil)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestCalibrationStore_RecordVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		verdicts    []Verdict
		wantAlpha   int
		wantBeta    int
	}{
		{
			name:      "confirmed increments alpha",
			verdicts:  []Verdict{VerdictConfirmed},
			wantAlpha: 1,
			wantBeta:  0,
		},
		{
			name:      "fixed increments alpha",
			verdicts:  []Verdict{VerdictFixed},
			wantAlpha: 1,
			wantBeta:  0,
		},
		{
			name:      "false_positive increments beta",
			verdicts:  []Verdict{VerdictFalsePositive},
			wantAlpha: 0,
			wantBeta:  1,
		},
		// accepted and missed are tested separately below because they produce no
		// bucket entry at all (GetBucket returns defaultPrior for missing keys).

		{
			name:      "confirmed then false_positive",
			verdicts:  []Verdict{VerdictConfirmed, VerdictFalsePositive},
			wantAlpha: 1,
			wantBeta:  1,
		},
		{
			name:      "multiple confirmed",
			verdicts:  []Verdict{VerdictConfirmed, VerdictConfirmed, VerdictFixed},
			wantAlpha: 3,
			wantBeta:  0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := openTempCalibration(t)
			const patternRef = "auth-flow/missing-auth-check"
			const fileGlob = "*.go"

			for _, v := range tc.verdicts {
				cs.RecordVerdict(patternRef, fileGlob, v)
			}

			key := NewBucketKey(patternRef, fileGlob)
			got := cs.GetBucket(key)
			if got.Alpha != tc.wantAlpha {
				t.Errorf("Alpha: got %d, want %d", got.Alpha, tc.wantAlpha)
			}
			if got.Beta != tc.wantBeta {
				t.Errorf("Beta: got %d, want %d", got.Beta, tc.wantBeta)
			}
		})
	}
}

func TestCalibrationStore_RecordVerdict_NoOpVerdicts(t *testing.T) {
	t.Parallel()

	noOpVerdicts := []Verdict{VerdictAccepted, VerdictMissed}

	for _, v := range noOpVerdicts {
		v := v
		t.Run(string(v), func(t *testing.T) {
			t.Parallel()
			cs := openTempCalibration(t)
			cs.RecordVerdict("pat/noop", "*.go", v)

			// No bucket should have been created.
			buckets := cs.Buckets()
			key := NewBucketKey("pat/noop", "*.go")
			if _, exists := buckets[key]; exists {
				t.Errorf("verdict %q should not create a bucket entry", v)
			}
		})
	}
}

func TestCalibrationStore_ConfidenceFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setup      func(cs *CalibrationStore)
		patternRef string
		file       string
		wantLow    float64 // inclusive lower bound
		wantHigh   float64 // inclusive upper bound
	}{
		{
			name: "exact bucket with enough samples",
			setup: func(cs *CalibrationStore) {
				// Add 5 confirmed (α=5, β=0 → well above min samples)
				for i := 0; i < 5; i++ {
					cs.RecordVerdict("pat/a", "*.go", VerdictConfirmed)
				}
			},
			patternRef: "pat/a",
			file:       "src/foo.go",
			wantLow:    0.99, // 5/(5+0) = 1.0 but bucket started at alpha=0
			wantHigh:   1.01,
		},
		{
			name: "wildcard bucket fallback",
			setup: func(cs *CalibrationStore) {
				// Add to wildcard bucket only
				for i := 0; i < 5; i++ {
					cs.RecordVerdict("pat/b", "*", VerdictConfirmed)
				}
				// No exact *.ts bucket
			},
			patternRef: "pat/b",
			file:       "handler.ts",
			wantLow:    0.99,
			wantHigh:   1.01,
		},
		{
			name: "global prior fallback when no bucket",
			setup: func(cs *CalibrationStore) {
				// Directly inject a global prior by importing
				data, _ := json.Marshal(calibrationFile{
					Version:      calibrationFileVersion,
					Buckets:      map[BucketKey]BetaBucket{},
					GlobalPriors: map[string]BetaBucket{"pat/c": {Alpha: 3, Beta: 7}},
				})
				_ = cs.Import(data, false)
			},
			patternRef: "pat/c",
			file:       "main.py",
			// global prior α=3, β=7 → 3/10 = 0.3
			wantLow:  0.29,
			wantHigh: 0.31,
		},
		{
			name:       "default prior fallback when nothing exists",
			setup:      func(cs *CalibrationStore) {},
			patternRef: "unknown/pattern",
			file:       "anything.go",
			// default prior α=1, β=1 → 0.5
			wantLow:  0.49,
			wantHigh: 0.51,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := openTempCalibration(t)
			tc.setup(cs)

			got := cs.ConfidenceFor(tc.patternRef, tc.file)
			if got < tc.wantLow || got > tc.wantHigh {
				t.Errorf("ConfidenceFor(%q, %q) = %.4f, want [%.4f, %.4f]",
					tc.patternRef, tc.file, got, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

func TestCalibrationStore_MinSampleGuard(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// Inject a global prior with known confidence via import.
	globalData, err := json.Marshal(calibrationFile{
		Version: calibrationFileVersion,
		Buckets: map[BucketKey]BetaBucket{},
		GlobalPriors: map[string]BetaBucket{
			"sec/check": {Alpha: 8, Beta: 2}, // global: 8/10 = 0.8
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cs.Import(globalData, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Add only 3 samples to the exact bucket (below minSampleThreshold=5).
	for i := 0; i < 3; i++ {
		cs.RecordVerdict("sec/check", "*.go", VerdictFalsePositive)
	}

	// With 3 samples only, should fall back to global prior (0.8), not exact bucket (0/3 ≈ 0.0).
	got := cs.ConfidenceFor("sec/check", "main.go")
	// Expect global prior confidence ~0.8, not ~0.0 from the under-sampled bucket.
	if got < 0.75 || got > 0.85 {
		t.Errorf("MinSampleGuard: got confidence %.4f, want ~0.8 (global prior)", got)
	}
}

func TestCalibrationStore_TimeDecay(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// Seed a bucket with a stale LastUpdate.
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	staleKey := NewBucketKey("crypto/weak", "*.go")

	// Inject stale bucket directly via Import.
	data, err := json.Marshal(calibrationFile{
		Version: calibrationFileVersion,
		Buckets: map[BucketKey]BetaBucket{
			staleKey: {Alpha: 10, Beta: 10, LastUpdate: oldTime},
		},
		GlobalPriors: map[string]BetaBucket{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cs.Import(data, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Apply decay: buckets older than 24h get multiplied by 0.5.
	cs.ApplyTimeDecay(24*time.Hour, 0.5)

	got := cs.GetBucket(staleKey)
	// 10 * 0.5 = 5, rounded
	if got.Alpha != 5 {
		t.Errorf("Alpha after decay: got %d, want 5", got.Alpha)
	}
	if got.Beta != 5 {
		t.Errorf("Beta after decay: got %d, want 5", got.Beta)
	}
}

func TestCalibrationStore_TimeDecay_MinimumOne(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	key := NewBucketKey("crypto/tiny", "*.go")

	data, err := json.Marshal(calibrationFile{
		Version:      calibrationFileVersion,
		Buckets:      map[BucketKey]BetaBucket{key: {Alpha: 1, Beta: 1, LastUpdate: oldTime}},
		GlobalPriors: map[string]BetaBucket{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := cs.Import(data, false); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// Apply aggressive decay — result should be clamped to 1.
	cs.ApplyTimeDecay(24*time.Hour, 0.1)

	got := cs.GetBucket(key)
	if got.Alpha < 1 {
		t.Errorf("Alpha after decay clamped: got %d, want >= 1", got.Alpha)
	}
	if got.Beta < 1 {
		t.Errorf("Beta after decay clamped: got %d, want >= 1", got.Beta)
	}
}

func TestCalibrationStore_TimeDecay_RecentBucketUnchanged(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// A fresh verdict is recent — should NOT be decayed.
	cs.RecordVerdict("pat/recent", "*.go", VerdictConfirmed)
	cs.RecordVerdict("pat/recent", "*.go", VerdictConfirmed)

	// Apply decay with maxAge=24h — the recently updated bucket should be untouched.
	cs.ApplyTimeDecay(24*time.Hour, 0.5)

	key := NewBucketKey("pat/recent", "*.go")
	got := cs.GetBucket(key)
	if got.Alpha != 2 {
		t.Errorf("Alpha should be unchanged: got %d, want 2", got.Alpha)
	}
}

func TestCalibrationStore_ExportImport(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// Seed some data.
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)
	cs.RecordVerdict("auth/check", "*.go", VerdictFalsePositive)

	raw, err := cs.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Verify the exported JSON is valid.
	var cf calibrationFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("parse exported JSON: %v", err)
	}

	key := NewBucketKey("auth/check", "*.go")
	b, ok := cf.Buckets[key]
	if !ok {
		t.Fatal("expected auth/check:*.go in exported JSON")
	}
	if b.Alpha != 2 {
		t.Errorf("exported Alpha: got %d, want 2", b.Alpha)
	}
	if b.Beta != 1 {
		t.Errorf("exported Beta: got %d, want 1", b.Beta)
	}
}

func TestCalibrationStore_ImportMerge(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// Seed local data: α=2, β=1.
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)
	cs.RecordVerdict("auth/check", "*.go", VerdictFalsePositive)

	// Import with merge=true: adds α=3, β=2 to existing.
	key := NewBucketKey("auth/check", "*.go")
	importData, err := json.Marshal(calibrationFile{
		Version:      calibrationFileVersion,
		Buckets:      map[BucketKey]BetaBucket{key: {Alpha: 3, Beta: 2}},
		GlobalPriors: map[string]BetaBucket{},
	})
	if err != nil {
		t.Fatalf("marshal import data: %v", err)
	}
	if err := cs.Import(importData, true); err != nil {
		t.Fatalf("Import merge: %v", err)
	}

	got := cs.GetBucket(key)
	if got.Alpha != 5 { // 2 + 3
		t.Errorf("merged Alpha: got %d, want 5", got.Alpha)
	}
	if got.Beta != 3 { // 1 + 2
		t.Errorf("merged Beta: got %d, want 3", got.Beta)
	}
}

func TestCalibrationStore_ImportReplace(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	// Seed local data.
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)
	cs.RecordVerdict("auth/check", "*.go", VerdictConfirmed)

	key := NewBucketKey("auth/check", "*.go")
	importData, err := json.Marshal(calibrationFile{
		Version:      calibrationFileVersion,
		Buckets:      map[BucketKey]BetaBucket{key: {Alpha: 7, Beta: 3}},
		GlobalPriors: map[string]BetaBucket{},
	})
	if err != nil {
		t.Fatalf("marshal import data: %v", err)
	}
	// merge=false: replace existing bucket.
	if err := cs.Import(importData, false); err != nil {
		t.Fatalf("Import replace: %v", err)
	}

	got := cs.GetBucket(key)
	if got.Alpha != 7 {
		t.Errorf("replaced Alpha: got %d, want 7", got.Alpha)
	}
	if got.Beta != 3 {
		t.Errorf("replaced Beta: got %d, want 3", got.Beta)
	}
}

func TestCalibrationStore_BucketsCopy(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)
	cs.RecordVerdict("pat/x", "*.go", VerdictConfirmed)

	buckets := cs.Buckets()
	key := NewBucketKey("pat/x", "*.go")

	// Mutate the returned copy — should not affect the store.
	delete(buckets, key)

	buckets2 := cs.Buckets()
	if _, ok := buckets2[key]; !ok {
		t.Error("mutating Buckets() result affected the store")
	}
}

func TestCalibrationStore_SavePersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "calibration.json")
	cs, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	cs.RecordVerdict("auth/flow", "*.go", VerdictConfirmed)

	if err := cs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from disk and verify the bucket is present.
	cs2, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	key := NewBucketKey("auth/flow", "*.go")
	got := cs2.GetBucket(key)
	if got.Alpha != 1 {
		t.Errorf("Alpha after reload: got %d, want 1", got.Alpha)
	}
}

func TestCalibrationStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cs := openTempCalibration(t)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Writers: record confirmed verdicts.
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			pat := "conc/pat"
			glob := "*.go"
			cs.RecordVerdict(pat, glob, VerdictConfirmed)
		}(i)
	}

	// Writers: record false positive verdicts.
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			cs.RecordVerdict("conc/pat", "*.ts", VerdictFalsePositive)
		}(i)
	}

	// Readers.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = cs.ConfidenceFor("conc/pat", "main.go")
		}()
	}

	wg.Wait()

	key := NewBucketKey("conc/pat", "*.go")
	got := cs.GetBucket(key)
	if got.Alpha == 0 && got.Beta == 0 {
		t.Error("expected non-zero bucket after concurrent writes")
	}
}

func TestBucketKey_PatternRefAndFileGlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key       BucketKey
		wantPat   string
		wantGlob  string
	}{
		{NewBucketKey("auth/check", "*.go"), "auth/check", "*.go"},
		{NewBucketKey("inj/sql", "*"), "inj/sql", "*"},
		{NewBucketKey("a:b", "*.ts"), "a:b", "*.ts"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.key), func(t *testing.T) {
			t.Parallel()
			if got := tc.key.PatternRef(); got != tc.wantPat {
				t.Errorf("PatternRef: got %q, want %q", got, tc.wantPat)
			}
			if got := tc.key.FileGlob(); got != tc.wantGlob {
				t.Errorf("FileGlob: got %q, want %q", got, tc.wantGlob)
			}
		})
	}
}

func TestBetaBucket_Confidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		alpha, beta int
		want        float64
	}{
		{0, 0, 0.5},
		{1, 1, 0.5},
		{10, 0, 1.0},
		{0, 10, 0.0},
		{3, 7, 0.3},
		{8, 2, 0.8},
	}

	for _, tc := range tests {
		tc := tc
		t.Run("", func(t *testing.T) {
			t.Parallel()
			b := BetaBucket{Alpha: tc.alpha, Beta: tc.beta}
			got := b.Confidence()
			if got < tc.want-0.001 || got > tc.want+0.001 {
				t.Errorf("Confidence(%d, %d) = %.4f, want %.4f",
					tc.alpha, tc.beta, got, tc.want)
			}
		})
	}
}

func TestFileGlobFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"src/auth.controller.ts", "*.controller.ts"},
		{"query.go", "*.go"},
		{"src/main.py", "*.py"},
		{"path/to/file.test.js", "*.test.js"},
		{"noext", "*"},
		{".hidden", "*"},
		{"dir/.hidden", "*"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := fileGlobFor(tc.input)
			if got != tc.want {
				t.Errorf("fileGlobFor(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
