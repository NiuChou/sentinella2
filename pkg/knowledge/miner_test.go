package knowledge

import (
	"strings"
	"testing"
	"time"
)

// baseTime is a fixed timestamp used in all test entries.
var baseTime = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// makeFP returns a false_positive FeedbackEntry for a given pattern and file.
func makeFP(patternRef, file string) FeedbackEntry {
	return FeedbackEntry{
		FindingID:  "test-" + patternRef + "-" + file,
		PatternRef: patternRef,
		File:       file,
		Verdict:    VerdictFalsePositive,
		Timestamp:  baseTime,
	}
}

// makeConfirmed returns a confirmed FeedbackEntry for a given pattern and file.
func makeConfirmed(patternRef, file string) FeedbackEntry {
	return FeedbackEntry{
		FindingID:  "test-conf-" + patternRef + "-" + file,
		PatternRef: patternRef,
		File:       file,
		Verdict:    VerdictConfirmed,
		Timestamp:  baseTime,
	}
}

// repeatFP produces n identical false positive entries.
func repeatFP(patternRef, file string, n int) []FeedbackEntry {
	entries := make([]FeedbackEntry, n)
	for i := range entries {
		e := makeFP(patternRef, file)
		e.FindingID = e.FindingID + "-" + string(rune('a'+i%26))
		entries[i] = e
	}
	return entries
}

// repeatConfirmed produces n identical confirmed entries.
func repeatConfirmed(patternRef, file string, n int) []FeedbackEntry {
	entries := make([]FeedbackEntry, n)
	for i := range entries {
		e := makeConfirmed(patternRef, file)
		e.FindingID = e.FindingID + "-" + string(rune('a'+i%26))
		entries[i] = e
	}
	return entries
}

func TestMiner_EmptyInput(t *testing.T) {
	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(nil)

	if len(result.Clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(result.Clusters))
	}
	if len(result.Suggested) != 0 {
		t.Errorf("expected 0 suggestions, got %d", len(result.Suggested))
	}
	if result.TotalAnalyzed != 0 {
		t.Errorf("expected TotalAnalyzed=0, got %d", result.TotalAnalyzed)
	}
}

func TestMiner_NoFalsePositives(t *testing.T) {
	entries := append(
		repeatConfirmed("auth-flow/missing-auth-check", "src/auth/auth.go", 10),
		repeatConfirmed("injection/sql-injection", "src/db/query.go", 5)...,
	)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 0 {
		t.Errorf("expected 0 clusters when all findings confirmed, got %d", len(result.Clusters))
	}
	if result.TotalAnalyzed != 15 {
		t.Errorf("expected TotalAnalyzed=15, got %d", result.TotalAnalyzed)
	}
}

func TestMiner_BasicClustering(t *testing.T) {
	// 9 FPs out of 10 total → 90% FP rate, above 80% threshold, 9 >= MinSamples(5).
	entries := append(
		repeatFP("auth-flow/missing-auth-check", "src/orders/orders.controller.ts", 9),
		makeConfirmed("auth-flow/missing-auth-check", "src/orders/orders.controller.ts"),
	)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}

	c := result.Clusters[0]
	if c.PatternRef != "auth-flow/missing-auth-check" {
		t.Errorf("expected pattern auth-flow/missing-auth-check, got %q", c.PatternRef)
	}
	if c.FilePattern != "*.controller.ts" {
		t.Errorf("expected file pattern *.controller.ts, got %q", c.FilePattern)
	}
	if c.FPCount != 9 {
		t.Errorf("expected FPCount=9, got %d", c.FPCount)
	}
	if c.TotalCount != 10 {
		t.Errorf("expected TotalCount=10, got %d", c.TotalCount)
	}
	if c.FPRate < 0.89 || c.FPRate > 0.91 {
		t.Errorf("expected FPRate≈0.90, got %.4f", c.FPRate)
	}
}

func TestMiner_MinSampleThreshold(t *testing.T) {
	// Only 4 FPs → below MinSamples=5, should not produce a cluster.
	entries := repeatFP("auth-flow/missing-auth-check", "src/orders/orders.controller.ts", 4)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 0 {
		t.Errorf("expected 0 clusters (below MinSamples), got %d", len(result.Clusters))
	}
}

func TestMiner_MinFPRateThreshold(t *testing.T) {
	// 5 FPs and 5 confirmed → 50% FP rate, below MinFPRate=0.8.
	entries := append(
		repeatFP("auth-flow/missing-auth-check", "src/orders/orders.controller.ts", 5),
		repeatConfirmed("auth-flow/missing-auth-check", "src/orders/orders.controller.ts", 5)...,
	)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 0 {
		t.Errorf("expected 0 clusters (FP rate 50%% below threshold 80%%), got %d", len(result.Clusters))
	}
}

func TestMiner_CompoundExtension(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "controller.ts",
			filePath: "src/orders/orders.controller.ts",
			want:     "*.controller.ts",
		},
		{
			name:     "service.ts",
			filePath: "src/auth/auth.service.ts",
			want:     "*.service.ts",
		},
		{
			name:     "spec.ts",
			filePath: "tests/auth.spec.ts",
			want:     "*.spec.ts",
		},
		{
			name:     "test.go",
			filePath: "pkg/auth/auth_test.go",
			want:     "*.go",
		},
		{
			name:     "deep path",
			filePath: "a/b/c/d/e.controller.ts",
			want:     "*.controller.ts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFilePattern(tt.filePath)
			if got != tt.want {
				t.Errorf("extractFilePattern(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestMiner_SimpleExtension(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{
			name:     "go file",
			filePath: "handlers/auth.go",
			want:     "*.go",
		},
		{
			name:     "sql file",
			filePath: "src/db/schema.sql",
			want:     "*.sql",
		},
		{
			name:     "py file",
			filePath: "api/views.py",
			want:     "*.py",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFilePattern(tt.filePath)
			if got != tt.want {
				t.Errorf("extractFilePattern(%q) = %q, want %q", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestExtractFilePattern(t *testing.T) {
	tests := []struct {
		filePath string
		want     string
	}{
		{"src/orders/orders.controller.ts", "*.controller.ts"},
		{"src/db/schema.sql", "*.sql"},
		{"handlers/auth.go", "*.go"},
		{"src/auth/auth.service.ts", "*.service.ts"},
		{"tests/unit.spec.ts", "*.spec.ts"},
		{"main.py", "*.py"},
		{"Makefile", "*"},
		{"", "*"},
		{"a/b/c.d.e.f", "*.e.f"},
	}

	for _, tt := range tests {
		got := extractFilePattern(tt.filePath)
		if got != tt.want {
			t.Errorf("extractFilePattern(%q) = %q, want %q", tt.filePath, got, tt.want)
		}
	}
}

func TestMiner_MultipleClusters(t *testing.T) {
	entries := []FeedbackEntry{}

	// Pattern 1: auth-flow on *.controller.ts — 8 FPs out of 9 total (88.9% FP rate)
	entries = append(entries, repeatFP("auth-flow/missing-auth-check", "src/a.controller.ts", 8)...)
	entries = append(entries, makeConfirmed("auth-flow/missing-auth-check", "src/a.controller.ts"))

	// Pattern 2: injection/sql-injection on *.sql — 6 FPs out of 7 total (85.7% FP rate)
	entries = append(entries, repeatFP("injection/sql-injection", "src/db/schema.sql", 6)...)
	entries = append(entries, makeConfirmed("injection/sql-injection", "src/db/schema.sql"))

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(result.Clusters))
	}

	// Clusters should be sorted by descending FP rate.
	if result.Clusters[0].FPRate < result.Clusters[1].FPRate {
		t.Errorf("clusters not sorted by descending FP rate: [0]=%.3f [1]=%.3f",
			result.Clusters[0].FPRate, result.Clusters[1].FPRate)
	}

	// Collect pattern refs.
	patternRefs := map[string]bool{
		result.Clusters[0].PatternRef: true,
		result.Clusters[1].PatternRef: true,
	}
	if !patternRefs["auth-flow/missing-auth-check"] {
		t.Error("expected auth-flow/missing-auth-check cluster")
	}
	if !patternRefs["injection/sql-injection"] {
		t.Error("expected injection/sql-injection cluster")
	}
}

func TestMiner_SuggestedActions(t *testing.T) {
	tests := []struct {
		name          string
		fpCount       int
		totalCount    int
		wantMemory    bool
		wantException bool
	}{
		{
			name:          "high FP rate (90%) → memory only",
			fpCount:       9,
			totalCount:    10,
			wantMemory:    true,
			wantException: false,
		},
		{
			name:          "very high FP rate (>95%) → exception + memory",
			fpCount:       10,
			totalCount:    10,
			wantMemory:    true,
			wantException: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := make([]FeedbackEntry, 0, tt.totalCount)
			entries = append(entries, repeatFP("auth-flow/test", "src/a.controller.ts", tt.fpCount)...)
			confirmed := tt.totalCount - tt.fpCount
			if confirmed > 0 {
				entries = append(entries, repeatConfirmed("auth-flow/test", "src/a.controller.ts", confirmed)...)
			}

			miner := NewMiner(DefaultMinerConfig())
			result := miner.Mine(entries)

			if len(result.Clusters) == 0 {
				t.Fatal("expected at least 1 cluster")
			}

			var hasMemory, hasException bool
			for _, s := range result.Suggested {
				switch s.Type {
				case SuggestMemory:
					hasMemory = true
					if s.MemoryText == "" {
						t.Error("SuggestMemory action has empty MemoryText")
					}
				case SuggestException:
					hasException = true
					if s.ConfigYAML == "" {
						t.Error("SuggestException action has empty ConfigYAML")
					}
				}
			}

			if hasMemory != tt.wantMemory {
				t.Errorf("hasMemory=%v, want %v", hasMemory, tt.wantMemory)
			}
			if hasException != tt.wantException {
				t.Errorf("hasException=%v, want %v", hasException, tt.wantException)
			}
		})
	}
}

func TestMiner_SuggestedActionContent(t *testing.T) {
	// 9 FPs out of 9 total → 100% FP rate → exception + memory.
	entries := repeatFP("auth-flow/missing-auth-check", "src/orders/orders.controller.ts", 10)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) == 0 {
		t.Fatal("expected at least 1 cluster")
	}

	for _, s := range result.Suggested {
		if s.Cluster.PatternRef == "" {
			t.Error("suggested action has empty cluster PatternRef")
		}
		switch s.Type {
		case SuggestMemory:
			if !strings.Contains(s.MemoryText, "auth-flow/missing-auth-check") {
				t.Errorf("MemoryText does not contain pattern ref: %q", s.MemoryText)
			}
			if !strings.Contains(s.MemoryText, "*.controller.ts") {
				t.Errorf("MemoryText does not contain file pattern: %q", s.MemoryText)
			}
		case SuggestException:
			if !strings.Contains(s.ConfigYAML, "auth-flow/missing-auth-check") {
				t.Errorf("ConfigYAML does not contain pattern ref: %q", s.ConfigYAML)
			}
			if !strings.Contains(s.ConfigYAML, "*.controller.ts") {
				t.Errorf("ConfigYAML does not contain file pattern: %q", s.ConfigYAML)
			}
		}
	}
}

func TestMiner_CustomThresholds(t *testing.T) {
	// Use custom config: MinFPRate=0.5, MinSamples=3
	cfg := MinerConfig{MinFPRate: 0.5, MinSamples: 3}
	miner := NewMiner(cfg)

	// 3 FPs out of 5 total → 60% FP rate → meets custom 50% threshold and 3 samples.
	entries := append(
		repeatFP("auth-flow/missing-auth-check", "src/a.go", 3),
		repeatConfirmed("auth-flow/missing-auth-check", "src/a.go", 2)...,
	)

	result := miner.Mine(entries)

	if len(result.Clusters) != 1 {
		t.Errorf("expected 1 cluster with custom thresholds, got %d", len(result.Clusters))
	}
}

func TestMiner_TotalAnalyzedCount(t *testing.T) {
	entries := append(
		repeatFP("auth-flow/test", "src/a.go", 7),
		repeatConfirmed("auth-flow/test", "src/b.go", 3)...,
	)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if result.TotalAnalyzed != 10 {
		t.Errorf("expected TotalAnalyzed=10, got %d", result.TotalAnalyzed)
	}
}

func TestMiner_DifferentFilePatternsPerPattern(t *testing.T) {
	// Same pattern, two different file types — each should be a separate cluster.
	entries := append(
		repeatFP("injection/sql-injection", "src/a.controller.ts", 6),
		repeatFP("injection/sql-injection", "src/b.service.ts", 5)...,
	)

	miner := NewMiner(DefaultMinerConfig())
	result := miner.Mine(entries)

	if len(result.Clusters) != 2 {
		t.Fatalf("expected 2 clusters for different file patterns, got %d", len(result.Clusters))
	}

	patterns := map[string]bool{
		result.Clusters[0].FilePattern: true,
		result.Clusters[1].FilePattern: true,
	}
	if !patterns["*.controller.ts"] {
		t.Error("expected *.controller.ts cluster")
	}
	if !patterns["*.service.ts"] {
		t.Error("expected *.service.ts cluster")
	}
}
