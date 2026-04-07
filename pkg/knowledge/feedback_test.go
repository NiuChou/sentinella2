package knowledge

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOpenFeedbackStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr bool
	}{
		{
			name: "empty dir is created",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "feedback")
			},
		},
		{
			name: "existing empty dir loads zero entries",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
		},
		{
			name: "empty path returns error",
			setup: func(_ *testing.T) string {
				return ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := tt.setup(t)
			fs, err := OpenFeedbackStore(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(fs.Entries()); got != 0 {
				t.Fatalf("expected 0 entries, got %d", got)
			}
		})
	}
}

func validEntry(patternRef string, verdict Verdict) FeedbackEntry {
	return FeedbackEntry{
		FindingID:  "finding-001",
		PatternRef: patternRef,
		File:       "main.go",
		Line:       42,
		Verdict:    verdict,
		Reason:     "test reason",
		Timestamp:  time.Date(2026, 4, 6, 12, 0, 0, 0, time.UTC),
		Project:    "test-project",
	}
}

func TestFeedbackStoreAdd(t *testing.T) {
	t.Parallel()

	t.Run("valid entry is stored and returned", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		entry := validEntry("injection/sql", VerdictConfirmed)
		if err := store.Add(entry); err != nil {
			t.Fatalf("add: %v", err)
		}

		entries := store.Entries()
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].FindingID != "finding-001" {
			t.Errorf("expected finding_id finding-001, got %s", entries[0].FindingID)
		}
	})

	t.Run("empty finding_id returns error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		entry := validEntry("injection/sql", VerdictConfirmed)
		entry.FindingID = ""
		if err := store.Add(entry); err == nil {
			t.Fatal("expected error for empty finding_id")
		}
	})

	t.Run("empty pattern_ref returns error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		entry := validEntry("", VerdictConfirmed)
		entry.PatternRef = ""
		if err := store.Add(entry); err == nil {
			t.Fatal("expected error for empty pattern_ref")
		}
	})

	t.Run("invalid verdict returns error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		entry := validEntry("injection/sql", "invalid")
		if err := store.Add(entry); err == nil {
			t.Fatal("expected error for invalid verdict")
		}
	})

	t.Run("zero timestamp returns error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		entry := validEntry("injection/sql", VerdictConfirmed)
		entry.Timestamp = time.Time{}
		if err := store.Add(entry); err == nil {
			t.Fatal("expected error for zero timestamp")
		}
	})
}

func TestFeedbackStoreStats(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := OpenFeedbackStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Add entries across two patterns.
	entries := []FeedbackEntry{
		{FindingID: "f1", PatternRef: "auth/idor", Verdict: VerdictConfirmed, Timestamp: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Project: "p"},
		{FindingID: "f2", PatternRef: "auth/idor", Verdict: VerdictFalsePositive, Timestamp: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC), Project: "p"},
		{FindingID: "f3", PatternRef: "auth/idor", Verdict: VerdictConfirmed, Timestamp: time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC), Project: "p"},
		{FindingID: "f4", PatternRef: "injection/xss", Verdict: VerdictFalsePositive, Timestamp: time.Date(2026, 4, 4, 0, 0, 0, 0, time.UTC), Project: "p"},
		{FindingID: "f5", PatternRef: "injection/xss", Verdict: VerdictMissed, Timestamp: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), Project: "p"},
	}

	for _, e := range entries {
		if err := store.Add(e); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	stats := store.Stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}

	// Stats are sorted alphabetically; auth/idor comes first.
	authStats := stats[0]
	if authStats.PatternRef != "auth/idor" {
		t.Errorf("expected auth/idor first, got %s", authStats.PatternRef)
	}
	if authStats.TotalFeedback != 3 {
		t.Errorf("expected 3 total, got %d", authStats.TotalFeedback)
	}
	if authStats.Confirmed != 2 {
		t.Errorf("expected 2 confirmed, got %d", authStats.Confirmed)
	}
	if authStats.FalsePositives != 1 {
		t.Errorf("expected 1 FP, got %d", authStats.FalsePositives)
	}
	// FP rate = 1/(2+1) = 0.333...
	wantFPR := 1.0 / 3.0
	if math.Abs(authStats.FalsePositiveRate-wantFPR) > 0.001 {
		t.Errorf("expected FP rate ~%.3f, got %.3f", wantFPR, authStats.FalsePositiveRate)
	}
	// Precision = 2/(2+1) = 0.666...
	wantPrec := 2.0 / 3.0
	if math.Abs(authStats.Precision-wantPrec) > 0.001 {
		t.Errorf("expected precision ~%.3f, got %.3f", wantPrec, authStats.Precision)
	}
}

func TestFeedbackStoreStatsForPattern(t *testing.T) {
	t.Parallel()

	t.Run("no feedback returns zero values", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		store, err := OpenFeedbackStore(dir)
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		st := store.StatsForPattern("nonexistent/pattern")
		if st.PatternRef != "nonexistent/pattern" {
			t.Errorf("expected pattern ref set, got %q", st.PatternRef)
		}
		if st.TotalFeedback != 0 {
			t.Errorf("expected 0 total, got %d", st.TotalFeedback)
		}
		if st.FalsePositiveRate != 0 {
			t.Errorf("expected 0 FP rate, got %f", st.FalsePositiveRate)
		}
	})
}

func TestFeedbackStoreConcurrency(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := OpenFeedbackStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			entry := FeedbackEntry{
				FindingID:  "finding-concurrent",
				PatternRef: "concurrent/test",
				Verdict:    VerdictConfirmed,
				Timestamp:  time.Date(2026, 4, 6, 0, 0, n, 0, time.UTC),
				Project:    "p",
			}
			_ = store.Add(entry)
		}(i)
	}
	wg.Wait()

	if got := len(store.Entries()); got != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, got)
	}
}

func TestFeedbackStoreMonthlyFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := OpenFeedbackStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Add entries in two different months.
	march := FeedbackEntry{
		FindingID: "f-march", PatternRef: "p/a", Verdict: VerdictConfirmed,
		Timestamp: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), Project: "p",
	}
	april := FeedbackEntry{
		FindingID: "f-april", PatternRef: "p/a", Verdict: VerdictFalsePositive,
		Timestamp: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), Project: "p",
	}

	if err := store.Add(march); err != nil {
		t.Fatalf("add march: %v", err)
	}
	if err := store.Add(april); err != nil {
		t.Fatalf("add april: %v", err)
	}

	// Verify two separate files were created.
	if _, err := os.Stat(filepath.Join(dir, "2026-03.yaml")); err != nil {
		t.Errorf("expected 2026-03.yaml: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-04.yaml")); err != nil {
		t.Errorf("expected 2026-04.yaml: %v", err)
	}

	// Reopen store and verify entries survive reload.
	store2, err := OpenFeedbackStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := len(store2.Entries()); got != 2 {
		t.Errorf("expected 2 entries after reload, got %d", got)
	}
}

func TestFeedbackStoreExport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := OpenFeedbackStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	entry := validEntry("injection/sql", VerdictConfirmed)
	if err := store.Add(entry); err != nil {
		t.Fatalf("add: %v", err)
	}

	var buf bytes.Buffer
	if err := store.Export(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("expected non-empty export output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("schema_version")) {
		t.Error("expected schema_version in export output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("finding-001")) {
		t.Error("expected finding ID in export output")
	}
}

func TestVerdictIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		verdict Verdict
		want    bool
	}{
		{VerdictConfirmed, true},
		{VerdictFalsePositive, true},
		{VerdictMissed, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.verdict), func(t *testing.T) {
			t.Parallel()
			if got := tt.verdict.IsValid(); got != tt.want {
				t.Errorf("Verdict(%q).IsValid() = %v, want %v", tt.verdict, got, tt.want)
			}
		})
	}
}
