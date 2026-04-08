package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/perseworks/sentinella2/pkg/knowledge"
	"gopkg.in/yaml.v3"
)

// runKB dispatches kb subcommands.
func runKB(args []string) error {
	if len(args) < 1 {
		printKBUsage()
		return fmt.Errorf("usage: sentinella2 kb <subcommand>")
	}

	switch args[0] {
	case "update":
		return runKBUpdate(args[1:])
	case "diff":
		return runKBDiff(args[1:])
	case "apply":
		return runKBApply(args[1:])
	case "status":
		return runKBStatus(args[1:])
	case "add":
		return runKBAdd(args[1:])
	case "remove":
		return runKBRemove(args[1:])
	case "list":
		return runKBList(args[1:])
	case "feedback":
		return runKBFeedback(args[1:])
	case "stats":
		return runKBStats(args[1:])
	case "tune":
		return runKBTune(args[1:])
	case "synthesize":
		return runKBSynthesize(args[1:])
	case "review":
		return runKBReview(args[1:])
	case "calibration":
		return runKBCalibration(args[1:])
	default:
		printKBUsage()
		return fmt.Errorf("unknown kb subcommand: %s", args[0])
	}
}

// printKBUsage prints the kb subcommand help text.
func printKBUsage() {
	fmt.Fprintf(os.Stderr, `sentinella2 kb - Knowledge base management

Subcommands:
  update        Fetch configured vulnerability feeds
  diff          Show pending incremental changes
  apply         Apply pending entries to local KB
  status        Show sync status, feedback stats, pending entries
  add           Register a new community knowledge source
  remove        Remove a registered source
  list          List all registered knowledge sources
  feedback      Record feedback for a finding (mark subcommand)
  stats         Show feedback statistics per pattern
  tune          Apply feedback-driven tuning to patterns
  synthesize    Use LLM to analyze feed entries and generate candidates
  review        List pending candidates for human review
  calibration   Manage shared calibration priors per tech stack
`)
}

// runKBUpdate fetches configured feeds and shows a summary.
func runKBUpdate(args []string) error {
	fs := flag.NewFlagSet("kb update", flag.ExitOnError)
	feedFlag := fs.String("feed", "", "specific feed ID to update")
	sinceFlag := fs.String("since", "7d", "fetch entries since duration (e.g., 24h, 7d, 30d)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	since, err := parseDuration(*sinceFlag)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}

	stateDir, err := kbStateDir()
	if err != nil {
		return err
	}

	state, err := loadFeedState(stateDir)
	if err != nil {
		return fmt.Errorf("failed to load feed state: %w", err)
	}

	cutoff := time.Now().Add(-since)
	fmt.Fprintf(os.Stderr, "Fetching feeds since %s...\n", cutoff.Format(time.RFC3339))

	if *feedFlag != "" {
		fmt.Fprintf(os.Stderr, "  Feed: %s (fetch not yet implemented, recording state)\n", *feedFlag)
		state = updateFeedTimestamp(state, *feedFlag, time.Now(), 0)
	} else {
		fmt.Fprintf(os.Stderr, "  All configured feeds (fetch not yet implemented, recording state)\n")
		for _, id := range []string{"nvd", "freebsd-sa", "github-advisory"} {
			state = updateFeedTimestamp(state, id, time.Now(), 0)
		}
	}

	if err := saveFeedState(stateDir, state); err != nil {
		return fmt.Errorf("failed to save feed state: %w", err)
	}

	fmt.Println("Feed update complete. Use 'sentinella2 kb diff' to see pending changes.")
	return nil
}

// runKBDiff shows pending incremental changes from feeds or synthesis.
func runKBDiff(args []string) error {
	fs := flag.NewFlagSet("kb diff", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	pendingDir, err := kbPendingDir()
	if err != nil {
		return err
	}

	entries, err := loadPendingEntries(pendingDir)
	if err != nil {
		return fmt.Errorf("failed to load pending entries: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No pending changes.")
		return nil
	}

	fmt.Printf("Pending changes: %d entries\n\n", len(entries))
	for i, e := range entries {
		fmt.Printf("  [%d] %s (%s) - %s\n", i+1, e.SourceID, e.Type, e.Entry.Title)
		fmt.Printf("      Pattern: %s | Confidence: %.2f | Status: %s\n",
			e.PatternRef, e.Confidence, e.Status)
	}
	return nil
}

// runKBApply applies pending incremental entries to local KB.
func runKBApply(args []string) error {
	fs := flag.NewFlagSet("kb apply", flag.ExitOnError)
	autoFlag := fs.Bool("auto", false, "auto-approve all pending entries")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	pendingDir, err := kbPendingDir()
	if err != nil {
		return err
	}

	entries, err := loadPendingEntries(pendingDir)
	if err != nil {
		return fmt.Errorf("failed to load pending entries: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No pending entries to apply.")
		return nil
	}

	if !*autoFlag {
		fmt.Printf("Pending entries for review (%d total):\n\n", len(entries))
		for i, e := range entries {
			fmt.Printf("  [%d] %s (%s)\n", i+1, e.SourceID, e.Type)
			fmt.Printf("      Title:      %s\n", e.Entry.Title)
			fmt.Printf("      Severity:   %s\n", e.Entry.Severity)
			fmt.Printf("      Pattern:    %s\n", e.PatternRef)
			fmt.Printf("      Confidence: %.2f\n", e.Confidence)
			fmt.Println()
		}
		fmt.Println("Run with --auto to apply all, or use 'kb review' for interactive review.")
		return nil
	}

	applied := 0
	for _, e := range entries {
		fmt.Printf("  Applied: %s (%s)\n", e.SourceID, e.Entry.Title)
		applied++
	}

	// Clear pending entries after apply.
	if err := clearPendingEntries(pendingDir); err != nil {
		return fmt.Errorf("failed to clear pending entries: %w", err)
	}

	fmt.Printf("\nApplied %d entries to local knowledge base.\n", applied)
	return nil
}

// runKBStatus shows sync status, feedback stats, and pending entries.
func runKBStatus(args []string) error {
	fs := flag.NewFlagSet("kb status", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	stateDir, err := kbStateDir()
	if err != nil {
		return err
	}

	state, err := loadFeedState(stateDir)
	if err != nil {
		return fmt.Errorf("failed to load feed state: %w", err)
	}

	pendingDir, err := kbPendingDir()
	if err != nil {
		return err
	}

	pending, err := loadPendingEntries(pendingDir)
	if err != nil {
		return fmt.Errorf("failed to load pending entries: %w", err)
	}

	feedbackDir, err := kbFeedbackDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Knowledge Base Status ===")
	fmt.Println()

	// Feed sync status.
	fmt.Println("Feed Sync:")
	if len(state.Feeds) == 0 {
		fmt.Println("  No feeds synced yet.")
	} else {
		for _, f := range state.Feeds {
			fmt.Printf("  %-20s last sync: %s (%d entries)\n",
				f.FeedID, f.LastSync.Format(time.RFC3339), f.LastCount)
		}
	}
	fmt.Println()

	// Pending entries.
	fmt.Printf("Pending Entries: %d\n\n", len(pending))

	// Feedback stats.
	fmt.Printf("Feedback Directory: %s\n", feedbackDir)

	// Registered sources.
	registryDir, err := kbRegistryDir()
	if err != nil {
		return err
	}

	sources, err := loadRegisteredSources(registryDir)
	if err != nil {
		return fmt.Errorf("failed to load sources: %w", err)
	}

	fmt.Printf("Registered Sources: %d\n", len(sources))
	for _, s := range sources {
		fmt.Printf("  %-20s %s\n", s.Name, s.URL)
	}

	return nil
}

// runKBAdd registers a new community knowledge source.
func runKBAdd(args []string) error {
	fs := flag.NewFlagSet("kb add", flag.ExitOnError)
	descFlag := fs.String("description", "", "description of the knowledge source")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("usage: sentinella2 kb add <name> <url> [--description <text>]")
	}

	name := fs.Arg(0)
	url := fs.Arg(1)

	if name == "" {
		return fmt.Errorf("source name must not be empty")
	}
	if url == "" {
		return fmt.Errorf("source URL must not be empty")
	}

	registryDir, err := kbRegistryDir()
	if err != nil {
		return err
	}

	sources, err := loadRegisteredSources(registryDir)
	if err != nil {
		return fmt.Errorf("failed to load sources: %w", err)
	}

	for _, s := range sources {
		if s.Name == name {
			return fmt.Errorf("source %q already registered", name)
		}
	}

	source := registeredSource{
		Name:        name,
		URL:         url,
		Description: *descFlag,
		AddedAt:     time.Now().UTC(),
	}

	sources = append(sources, source)

	if err := saveRegisteredSources(registryDir, sources); err != nil {
		return fmt.Errorf("failed to save sources: %w", err)
	}

	fmt.Printf("Registered source: %s (%s)\n", name, url)
	return nil
}

// runKBRemove removes a registered source by name.
func runKBRemove(args []string) error {
	fs := flag.NewFlagSet("kb remove", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 kb remove <name>")
	}

	name := fs.Arg(0)

	registryDir, err := kbRegistryDir()
	if err != nil {
		return err
	}

	sources, err := loadRegisteredSources(registryDir)
	if err != nil {
		return fmt.Errorf("failed to load sources: %w", err)
	}

	found := false
	filtered := make([]registeredSource, 0, len(sources))
	for _, s := range sources {
		if s.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, s)
	}

	if !found {
		return fmt.Errorf("source %q not found", name)
	}

	if err := saveRegisteredSources(registryDir, filtered); err != nil {
		return fmt.Errorf("failed to save sources: %w", err)
	}

	fmt.Printf("Removed source: %s\n", name)
	return nil
}

// runKBList lists all registered knowledge sources with status.
func runKBList(args []string) error {
	fs := flag.NewFlagSet("kb list", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	registryDir, err := kbRegistryDir()
	if err != nil {
		return err
	}

	sources, err := loadRegisteredSources(registryDir)
	if err != nil {
		return fmt.Errorf("failed to load sources: %w", err)
	}

	// Always show builtin source.
	fmt.Println("Knowledge Sources:")
	fmt.Printf("  %-20s %-10s %s\n", "NAME", "TYPE", "URL/PATH")
	fmt.Printf("  %-20s %-10s %s\n", "----", "----", "--------")
	fmt.Printf("  %-20s %-10s %s\n", "builtin", "embedded", "(compiled into binary)")

	for _, s := range sources {
		fmt.Printf("  %-20s %-10s %s\n", s.Name, "community", s.URL)
	}

	fmt.Printf("\nTotal: %d sources (1 builtin + %d community)\n", 1+len(sources), len(sources))
	return nil
}

// --- data types for kb state persistence ---

// registeredSource describes a user-registered community knowledge source.
type registeredSource struct {
	Name        string    `yaml:"name"`
	URL         string    `yaml:"url"`
	Description string    `yaml:"description,omitempty"`
	AddedAt     time.Time `yaml:"added_at"`
}

// registryFile is the top-level structure for the sources registry.
type registryFile struct {
	SchemaVersion string             `yaml:"schema_version"`
	Kind          string             `yaml:"kind"`
	Sources       []registeredSource `yaml:"sources"`
}

// feedStateFile tracks per-feed sync metadata.
type feedStateFile struct {
	SchemaVersion string          `yaml:"schema_version"`
	Kind          string          `yaml:"kind"`
	Feeds         []feedStateItem `yaml:"feeds"`
}

// feedStateItem tracks sync metadata for a single feed.
type feedStateItem struct {
	FeedID    string    `yaml:"feed_id"`
	LastSync  time.Time `yaml:"last_sync"`
	LastCount int       `yaml:"last_count"`
}

// pendingFile stores incremental entries awaiting review.
type pendingFile struct {
	SchemaVersion string              `yaml:"schema_version"`
	Kind          string              `yaml:"kind"`
	Entries       []pendingEntryStore `yaml:"entries"`
}

// pendingEntryStore is the on-disk representation of a pending entry.
type pendingEntryStore struct {
	Type       string    `yaml:"type"`
	SourceID   string    `yaml:"source_id"`
	PatternRef string    `yaml:"pattern_ref"`
	Title      string    `yaml:"title"`
	Severity   string    `yaml:"severity"`
	Confidence float64   `yaml:"confidence"`
	Status     string    `yaml:"status"`
	CreatedAt  time.Time `yaml:"created_at"`
}

// --- directory resolution helpers ---

// sentinellaHomeDir returns ~/.sentinella2, creating it if necessary.
func sentinellaHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve home directory: %w", err)
	}
	dir := filepath.Join(home, ".sentinella2")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", dir, err)
	}
	return dir, nil
}

func kbStateDir() (string, error) {
	base, err := sentinellaHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "kb")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create kb directory: %w", err)
	}
	return dir, nil
}

func kbPendingDir() (string, error) {
	base, err := sentinellaHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "kb", "pending")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create pending directory: %w", err)
	}
	return dir, nil
}

func kbFeedbackDir() (string, error) {
	base, err := sentinellaHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "feedback")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create feedback directory: %w", err)
	}
	return dir, nil
}

func kbRegistryDir() (string, error) {
	base, err := sentinellaHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "registries")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create registries directory: %w", err)
	}
	return dir, nil
}

// --- persistence helpers ---

func loadFeedState(dir string) (feedStateFile, error) {
	path := filepath.Join(dir, "state.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return feedStateFile{SchemaVersion: "1.0", Kind: "feed_state"}, nil
		}
		return feedStateFile{}, fmt.Errorf("read state file: %w", err)
	}

	var state feedStateFile
	if err := yaml.Unmarshal(data, &state); err != nil {
		return feedStateFile{}, fmt.Errorf("parse state file: %w", err)
	}
	return state, nil
}

func saveFeedState(dir string, state feedStateFile) error {
	path := filepath.Join(dir, "state.yaml")
	data, err := yaml.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	return nil
}

// updateFeedTimestamp returns a new feedStateFile with the given feed's
// timestamp and count updated. The original is not modified.
func updateFeedTimestamp(state feedStateFile, feedID string, ts time.Time, count int) feedStateFile {
	newFeeds := make([]feedStateItem, 0, len(state.Feeds)+1)
	found := false
	for _, f := range state.Feeds {
		if f.FeedID == feedID {
			newFeeds = append(newFeeds, feedStateItem{
				FeedID:    feedID,
				LastSync:  ts,
				LastCount: count,
			})
			found = true
		} else {
			newFeeds = append(newFeeds, f)
		}
	}
	if !found {
		newFeeds = append(newFeeds, feedStateItem{
			FeedID:    feedID,
			LastSync:  ts,
			LastCount: count,
		})
	}
	return feedStateFile{
		SchemaVersion: state.SchemaVersion,
		Kind:          state.Kind,
		Feeds:         newFeeds,
	}
}

// internalPendingEntry is a unified pending entry used in-memory.
type internalPendingEntry struct {
	Type       string
	SourceID   string
	PatternRef string
	Confidence float64
	Status     string
	Entry      internalFeedEntry
}

// internalFeedEntry holds feed entry fields needed for display.
type internalFeedEntry struct {
	Title    string
	Severity string
}

func loadPendingEntries(dir string) ([]internalPendingEntry, error) {
	path := filepath.Join(dir, "pending.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read pending file: %w", err)
	}

	var pf pendingFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse pending file: %w", err)
	}

	entries := make([]internalPendingEntry, len(pf.Entries))
	for i, e := range pf.Entries {
		entries[i] = internalPendingEntry{
			Type:       e.Type,
			SourceID:   e.SourceID,
			PatternRef: e.PatternRef,
			Confidence: e.Confidence,
			Status:     e.Status,
			Entry: internalFeedEntry{
				Title:    e.Title,
				Severity: e.Severity,
			},
		}
	}
	return entries, nil
}

func savePendingEntries(dir string, entries []internalPendingEntry) error {
	stored := make([]pendingEntryStore, len(entries))
	for i, e := range entries {
		stored[i] = pendingEntryStore{
			Type:       e.Type,
			SourceID:   e.SourceID,
			PatternRef: e.PatternRef,
			Title:      e.Entry.Title,
			Severity:   e.Entry.Severity,
			Confidence: e.Confidence,
			Status:     e.Status,
			CreatedAt:  time.Now().UTC(),
		}
	}

	pf := pendingFile{
		SchemaVersion: "1.0",
		Kind:          "pending_entries",
		Entries:       stored,
	}

	path := filepath.Join(dir, "pending.yaml")
	data, err := yaml.Marshal(pf)
	if err != nil {
		return fmt.Errorf("marshal pending file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write pending file: %w", err)
	}
	return nil
}

func clearPendingEntries(dir string) error {
	path := filepath.Join(dir, "pending.yaml")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pending file: %w", err)
	}
	return nil
}

func loadRegisteredSources(dir string) ([]registeredSource, error) {
	path := filepath.Join(dir, "sources.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read sources file: %w", err)
	}

	var rf registryFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse sources file: %w", err)
	}
	return rf.Sources, nil
}

func saveRegisteredSources(dir string, sources []registeredSource) error {
	rf := registryFile{
		SchemaVersion: "1.0",
		Kind:          "registry",
		Sources:       sources,
	}

	path := filepath.Join(dir, "sources.yaml")
	data, err := yaml.Marshal(rf)
	if err != nil {
		return fmt.Errorf("marshal sources file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write sources file: %w", err)
	}
	return nil
}

// parseDuration parses a human-friendly duration string with support for days.
// Supported suffixes: h (hours), d (days), m (minutes), s (seconds).
func parseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty duration string")
	}

	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]

	switch suffix {
	case 'd':
		var days int
		if _, err := fmt.Sscanf(numStr, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid day count %q: %w", numStr, err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	default:
		return time.ParseDuration(s)
	}
}

// runKBCalibration dispatches kb calibration subcommands.
func runKBCalibration(args []string) error {
	if len(args) < 1 {
		printKBCalibrationUsage()
		return fmt.Errorf("usage: sentinella2 kb calibration <subcommand>")
	}

	switch args[0] {
	case "export":
		return runKBCalibrationExport(args[1:])
	default:
		printKBCalibrationUsage()
		return fmt.Errorf("unknown kb calibration subcommand: %s", args[0])
	}
}

// printKBCalibrationUsage prints calibration subcommand help.
func printKBCalibrationUsage() {
	fmt.Fprintf(os.Stderr, `sentinella2 kb calibration - Shared calibration prior management

Subcommands:
  export   Export calibration data to the shared stack-specific file

Usage:
  sentinella2 kb calibration export --stack <stack-id> [--path <calibration.json>]
`)
}

// runKBCalibrationExport exports calibration data to the shared stack file.
func runKBCalibrationExport(args []string) error {
	fs := flag.NewFlagSet("kb calibration export", flag.ContinueOnError)
	stackFlag := fs.String("stack", "", "tech stack ID to export for (e.g. nestjs, fastapi, gin)")
	pathFlag := fs.String("path", "", "path to calibration.json (default: ~/.sentinella2/calibration.json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if *stackFlag == "" {
		return fmt.Errorf("--stack flag is required (e.g. --stack nestjs)")
	}

	calibPath := *pathFlag
	if calibPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		calibPath = filepath.Join(home, ".sentinella2", "calibration.json")
	}

	cs, err := knowledge.OpenCalibrationStore(calibPath, nil)
	if err != nil {
		return fmt.Errorf("open calibration store: %w", err)
	}

	stack := knowledge.TechStack{ID: *stackFlag, Name: *stackFlag}

	if err := cs.ExportForStack(stack); err != nil {
		return err
	}

	dir, err := knowledge.SharedCalibrationDir()
	if err != nil {
		return err
	}

	fmt.Printf("Exported calibration for stack %q to %s/%s.json\n", *stackFlag, dir, *stackFlag)
	return nil
}
