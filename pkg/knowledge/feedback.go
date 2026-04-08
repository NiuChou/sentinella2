package knowledge

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Verdict represents the user's assessment of a scan finding.
type Verdict string

const (
	VerdictConfirmed     Verdict = "confirmed"
	VerdictFalsePositive Verdict = "false_positive"
	VerdictMissed        Verdict = "missed"
	// VerdictAccepted means the user acknowledges the risk but chooses not to
	// remediate. It does NOT feed into the Bayesian false-positive model.
	VerdictAccepted Verdict = "accepted"
	// VerdictFixed means the vulnerability was remediated; it counts as a true
	// positive in the Bayesian model.
	VerdictFixed Verdict = "fixed"
)

// IsValid reports whether v is a recognised verdict value.
func (v Verdict) IsValid() bool {
	switch v {
	case VerdictConfirmed, VerdictFalsePositive, VerdictMissed, VerdictAccepted, VerdictFixed:
		return true
	}
	return false
}

// feedbackSchemaVersion is the current schema version for feedback YAML files.
const feedbackSchemaVersion = "1.0"

// FeedbackEntry records a user's assessment of a single finding.
type FeedbackEntry struct {
	FindingID  string    `yaml:"finding_id"`
	PatternRef string    `yaml:"pattern_ref"`
	File       string    `yaml:"file"`
	Line       int       `yaml:"line"`
	Verdict    Verdict   `yaml:"verdict"`
	Reason     string    `yaml:"reason,omitempty"`
	Timestamp  time.Time `yaml:"timestamp"`
	Project    string    `yaml:"project"`
}

// RuleStats aggregates feedback statistics for a single pattern rule.
type RuleStats struct {
	PatternRef        string
	TotalFeedback     int
	Confirmed         int
	FalsePositives    int
	Missed            int
	FalsePositiveRate float64
	Precision         float64
}

// feedbackFile is the top-level structure of a monthly feedback YAML file.
type feedbackFile struct {
	SchemaVersion string          `yaml:"schema_version"`
	Kind          string          `yaml:"kind"`
	Month         string          `yaml:"month"`
	Entries       []FeedbackEntry `yaml:"entries"`
}

// FeedbackStore manages the append-only feedback database.
// Entries are stored as YAML files organized by month: feedback/2026-04.yaml
type FeedbackStore struct {
	mu      sync.RWMutex
	dir     string
	entries []FeedbackEntry
}

// OpenFeedbackStore loads all existing feedback from the directory.
// If the directory does not exist, it is created.
func OpenFeedbackStore(dir string) (*FeedbackStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("open feedback store: directory path must not be empty")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("open feedback store: create directory: %w", err)
	}

	entries, err := loadAllEntries(dir)
	if err != nil {
		return nil, fmt.Errorf("open feedback store: %w", err)
	}

	return &FeedbackStore{
		dir:     dir,
		entries: entries,
	}, nil
}

// Add appends a new feedback entry. It validates the entry, writes
// immediately to the current month's YAML file, and updates the in-memory cache.
func (fs *FeedbackStore) Add(entry FeedbackEntry) error {
	if err := validateEntry(entry); err != nil {
		return fmt.Errorf("add feedback: %w", err)
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := fs.appendToDisk(entry); err != nil {
		return fmt.Errorf("add feedback: %w", err)
	}

	fs.entries = append(fs.entries, entry)
	return nil
}

// Entries returns a copy of all feedback entries.
func (fs *FeedbackStore) Entries() []FeedbackEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return copyEntries(fs.entries)
}

// EntriesForPattern returns all feedback for a specific pattern ref.
func (fs *FeedbackStore) EntriesForPattern(patternRef string) []FeedbackEntry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var result []FeedbackEntry
	for _, e := range fs.entries {
		if e.PatternRef == patternRef {
			result = append(result, e)
		}
	}
	return result
}

// Stats returns aggregate statistics for all patterns with feedback,
// sorted alphabetically by PatternRef.
func (fs *FeedbackStore) Stats() []RuleStats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	grouped := make(map[string][]FeedbackEntry)
	for _, e := range fs.entries {
		grouped[e.PatternRef] = append(grouped[e.PatternRef], e)
	}

	stats := make([]RuleStats, 0, len(grouped))
	for ref, entries := range grouped {
		stats = append(stats, computeStats(ref, entries))
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].PatternRef < stats[j].PatternRef
	})
	return stats
}

// StatsForPattern returns statistics for a single pattern.
// If no feedback exists for the pattern, a zero-value RuleStats is returned
// with the PatternRef set.
func (fs *FeedbackStore) StatsForPattern(patternRef string) RuleStats {
	entries := fs.EntriesForPattern(patternRef)
	if len(entries) == 0 {
		return RuleStats{PatternRef: patternRef}
	}
	return computeStats(patternRef, entries)
}

// Export writes all entries as a single YAML file for portability.
func (fs *FeedbackStore) Export(w io.Writer) error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	file := feedbackFile{
		SchemaVersion: feedbackSchemaVersion,
		Kind:          "feedback",
		Month:         "all",
		Entries:       copyEntries(fs.entries),
	}

	enc := yaml.NewEncoder(w)
	defer enc.Close()
	enc.SetIndent(2)

	if err := enc.Encode(file); err != nil {
		return fmt.Errorf("export feedback: %w", err)
	}
	return nil
}

// --- internal helpers ---

// validateEntry checks that required fields are present and the verdict is valid.
func validateEntry(e FeedbackEntry) error {
	if e.FindingID == "" {
		return fmt.Errorf("finding_id must not be empty")
	}
	if e.PatternRef == "" {
		return fmt.Errorf("pattern_ref must not be empty")
	}
	if !e.Verdict.IsValid() {
		return fmt.Errorf("invalid verdict: %q", e.Verdict)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp must not be zero")
	}
	return nil
}

// monthKey returns the YYYY-MM string for a given time.
func monthKey(t time.Time) string {
	return t.Format("2006-01")
}

// monthFilePath returns the full path for a monthly feedback file.
func monthFilePath(dir, month string) string {
	return filepath.Join(dir, month+".yaml")
}

// loadAllEntries reads every YAML file in dir and returns all entries.
func loadAllEntries(dir string) ([]FeedbackEntry, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scan feedback files: %w", err)
	}

	var all []FeedbackEntry
	for _, path := range matches {
		entries, err := loadMonthFile(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", filepath.Base(path), err)
		}
		all = append(all, entries...)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.Before(all[j].Timestamp)
	})
	return all, nil
}

// loadMonthFile reads a single monthly YAML file and returns its entries.
func loadMonthFile(path string) ([]FeedbackEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var file feedbackFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if file.SchemaVersion != feedbackSchemaVersion {
		return nil, fmt.Errorf("unsupported schema version: %q (expected %q)",
			file.SchemaVersion, feedbackSchemaVersion)
	}

	return file.Entries, nil
}

// appendToDisk writes a single entry to the appropriate monthly file.
// If the file exists, it reads, appends, and rewrites it. If not, it creates a new one.
// Caller must hold fs.mu.
func (fs *FeedbackStore) appendToDisk(entry FeedbackEntry) error {
	month := monthKey(entry.Timestamp)
	path := monthFilePath(fs.dir, month)

	var file feedbackFile

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("parse existing file %s: %w", month, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read existing file %s: %w", month, err)
	} else {
		file = feedbackFile{
			SchemaVersion: feedbackSchemaVersion,
			Kind:          "feedback",
			Month:         month,
		}
	}

	file.Entries = append(file.Entries, entry)

	out, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshal feedback file %s: %w", month, err)
	}

	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write feedback file %s: %w", month, err)
	}
	return nil
}

// computeStats calculates aggregate statistics from a set of entries.
func computeStats(patternRef string, entries []FeedbackEntry) RuleStats {
	var confirmed, falsePositives, missed int
	for _, e := range entries {
		switch e.Verdict {
		case VerdictConfirmed:
			confirmed++
		case VerdictFalsePositive:
			falsePositives++
		case VerdictMissed:
			missed++
		}
	}

	total := confirmed + falsePositives
	var fpr, precision float64
	if total > 0 {
		fpr = float64(falsePositives) / float64(total)
		precision = float64(confirmed) / float64(total)
	}

	return RuleStats{
		PatternRef:        patternRef,
		TotalFeedback:     len(entries),
		Confirmed:         confirmed,
		FalsePositives:    falsePositives,
		Missed:            missed,
		FalsePositiveRate: fpr,
		Precision:         precision,
	}
}

// copyEntries returns a shallow copy of the entries slice.
func copyEntries(src []FeedbackEntry) []FeedbackEntry {
	if src == nil {
		return nil
	}
	dst := make([]FeedbackEntry, len(src))
	copy(dst, src)
	return dst
}
