package knowledge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openTempCalibrationAt creates a CalibrationStore at a specific path with no priors.
func openTempCalibrationAt(t *testing.T, path string) *CalibrationStore {
	t.Helper()
	cs, err := OpenCalibrationStore(path, nil)
	if err != nil {
		t.Fatalf("OpenCalibrationStore(%s): %v", path, err)
	}
	return cs
}

// sharedDirForTest overrides the shared calibration dir for a test by pointing
// HOME to a temp dir. Returns a cleanup function.
func withTempHome(t *testing.T) string {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	return tmpHome
}

func TestLoadStackPriors_NoFile(t *testing.T) {
	withTempHome(t)
	cs := openTempCalibration(t)

	stack := TechStack{ID: "nestjs", Name: "NestJS"}
	n, err := cs.LoadStackPriors(stack)
	if err != nil {
		t.Fatalf("LoadStackPriors: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("loaded: got %d, want 0 (no shared file)", n)
	}
}

func TestLoadStackPriors_EmptyStackID(t *testing.T) {
	withTempHome(t)
	cs := openTempCalibration(t)

	n, err := cs.LoadStackPriors(TechStack{})
	if err != nil {
		t.Fatalf("LoadStackPriors empty ID: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("loaded: got %d, want 0", n)
	}
}

func TestLoadStackPriors_LoadsNewBuckets(t *testing.T) {
	tmpHome := withTempHome(t)

	// Create a shared priors file with two buckets.
	sharedDir := filepath.Join(tmpHome, ".sentinella2", "calibration")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("mkdir shared dir: %v", err)
	}
	sharedData := calibrationFile{
		Version: calibrationFileVersion,
		Buckets: map[BucketKey]BetaBucket{
			NewBucketKey("sql-injection", "*.ts"): {Alpha: 3, Beta: 1, LastUpdate: time.Now().UTC()},
			NewBucketKey("xss", "*.ts"):           {Alpha: 2, Beta: 2, LastUpdate: time.Now().UTC()},
		},
		GlobalPriors: make(map[string]BetaBucket),
	}
	raw, err := json.MarshalIndent(sharedData, "", "  ")
	if err != nil {
		t.Fatalf("marshal shared data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sharedDir, "nestjs.json"), raw, 0o644); err != nil {
		t.Fatalf("write shared file: %v", err)
	}

	cs := openTempCalibration(t)
	stack := TechStack{ID: "nestjs", Name: "NestJS"}

	n, err := cs.LoadStackPriors(stack)
	if err != nil {
		t.Fatalf("LoadStackPriors: %v", err)
	}
	if n != 2 {
		t.Errorf("loaded: got %d, want 2", n)
	}

	// Both buckets should now be present.
	b1 := cs.GetBucket(NewBucketKey("sql-injection", "*.ts"))
	if b1.Alpha != 3 {
		t.Errorf("sql-injection alpha: got %d, want 3", b1.Alpha)
	}
}

func TestLoadStackPriors_NoOverwrite(t *testing.T) {
	tmpHome := withTempHome(t)

	// Create a shared priors file.
	sharedDir := filepath.Join(tmpHome, ".sentinella2", "calibration")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("mkdir shared dir: %v", err)
	}
	key := NewBucketKey("sql-injection", "*.py")
	sharedData := calibrationFile{
		Version: calibrationFileVersion,
		Buckets: map[BucketKey]BetaBucket{
			key: {Alpha: 10, Beta: 1},
		},
		GlobalPriors: make(map[string]BetaBucket),
	}
	raw, err := json.MarshalIndent(sharedData, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sharedDir, "fastapi.json"), raw, 0o644); err != nil {
		t.Fatalf("write shared file: %v", err)
	}

	// Store already has this bucket with learned data.
	cs := openTempCalibration(t)
	cs.RecordVerdict("sql-injection", "*.py", VerdictConfirmed) // alpha=2
	cs.RecordVerdict("sql-injection", "*.py", VerdictConfirmed) // alpha=3

	before := cs.GetBucket(key)

	stack := TechStack{ID: "fastapi", Name: "FastAPI"}
	n, err := cs.LoadStackPriors(stack)
	if err != nil {
		t.Fatalf("LoadStackPriors: %v", err)
	}
	// The existing bucket should not have been overwritten, so count = 0 new.
	if n != 0 {
		t.Errorf("loaded: got %d, want 0 (bucket already exists)", n)
	}

	after := cs.GetBucket(key)
	if after.Alpha != before.Alpha || after.Beta != before.Beta {
		t.Errorf("bucket changed: got alpha=%d beta=%d, want alpha=%d beta=%d",
			after.Alpha, after.Beta, before.Alpha, before.Beta)
	}
}

func TestExportForStack_Basic(t *testing.T) {
	tmpHome := withTempHome(t)

	cs := openTempCalibration(t)
	cs.RecordVerdict("sql-injection", "*.go", VerdictConfirmed)
	cs.RecordVerdict("xss", "*.html", VerdictFalsePositive)

	stack := TechStack{ID: "gin", Name: "Gin (Go)"}
	if err := cs.ExportForStack(stack); err != nil {
		t.Fatalf("ExportForStack: %v", err)
	}

	// Verify the exported file exists and contains the expected data.
	sharedPath := filepath.Join(tmpHome, ".sentinella2", "calibration", "gin.json")
	data, err := os.ReadFile(sharedPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}

	var cf calibrationFile
	if err := json.Unmarshal(data, &cf); err != nil {
		t.Fatalf("parse exported file: %v", err)
	}

	sqlKey := NewBucketKey("sql-injection", "*.go")
	if b, ok := cf.Buckets[sqlKey]; !ok {
		t.Errorf("sql-injection bucket missing in export")
	} else if b.Alpha < 1 {
		t.Errorf("sql-injection alpha: got %d, want >= 1", b.Alpha)
	}
}

func TestExportForStack_EmptyStackID(t *testing.T) {
	withTempHome(t)
	cs := openTempCalibration(t)

	err := cs.ExportForStack(TechStack{})
	if err == nil {
		t.Fatal("ExportForStack with empty ID: expected error, got nil")
	}
}
