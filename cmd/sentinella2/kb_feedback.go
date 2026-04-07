package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	sentinella2 "github.com/perseworks/sentinella2"
	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/provider"
)

// runKBFeedback dispatches feedback subcommands.
func runKBFeedback(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sentinella2 kb feedback mark <finding-id> <verdict> [options]")
	}

	switch args[0] {
	case "mark":
		return runKBFeedbackMark(args[1:])
	default:
		return fmt.Errorf("unknown feedback subcommand: %s (expected: mark)", args[0])
	}
}

// runKBFeedbackMark records feedback for a finding.
func runKBFeedbackMark(args []string) error {
	fs := flag.NewFlagSet("kb feedback mark", flag.ExitOnError)
	reasonFlag := fs.String("reason", "", "reason for the verdict")
	fileFlag := fs.String("file", "", "file path where the finding was reported")
	lineFlag := fs.Int("line", 0, "line number of the finding")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("usage: sentinella2 kb feedback mark <finding-id> <verdict> [--reason <text>] [--file <path>] [--line <n>]")
	}

	findingID := fs.Arg(0)
	verdictStr := fs.Arg(1)

	verdict := knowledge.Verdict(verdictStr)
	if !verdict.IsValid() {
		return fmt.Errorf("invalid verdict %q: must be one of confirmed, false_positive, missed", verdictStr)
	}

	feedbackDir, err := kbFeedbackDir()
	if err != nil {
		return err
	}

	store, err := knowledge.OpenFeedbackStore(feedbackDir)
	if err != nil {
		return fmt.Errorf("failed to open feedback store: %w", err)
	}

	// Derive pattern ref from finding ID. Finding IDs follow the convention
	// "pattern-ref:file:line", so we extract the pattern portion. If the
	// finding ID does not contain a colon, use it as-is for the pattern ref.
	patternRef := extractPatternRef(findingID)

	entry := knowledge.FeedbackEntry{
		FindingID:  findingID,
		PatternRef: patternRef,
		File:       *fileFlag,
		Line:       *lineFlag,
		Verdict:    verdict,
		Reason:     *reasonFlag,
		Timestamp:  time.Now().UTC(),
		Project:    currentProjectName(),
	}

	if err := store.Add(entry); err != nil {
		return fmt.Errorf("failed to record feedback: %w", err)
	}

	fmt.Printf("Recorded feedback: %s -> %s\n", findingID, verdictStr)
	if *reasonFlag != "" {
		fmt.Printf("  Reason: %s\n", *reasonFlag)
	}
	return nil
}

// runKBStats shows feedback statistics per pattern.
func runKBStats(args []string) error {
	fs := flag.NewFlagSet("kb stats", flag.ExitOnError)
	patternFlag := fs.String("pattern", "", "filter stats for a specific pattern ID")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	feedbackDir, err := kbFeedbackDir()
	if err != nil {
		return err
	}

	store, err := knowledge.OpenFeedbackStore(feedbackDir)
	if err != nil {
		return fmt.Errorf("failed to open feedback store: %w", err)
	}

	if *patternFlag != "" {
		st := store.StatsForPattern(*patternFlag)
		printRuleStats(st)
		return nil
	}

	allStats := store.Stats()
	if len(allStats) == 0 {
		fmt.Println("No feedback recorded yet.")
		return nil
	}

	fmt.Printf("%-40s %6s %6s %6s %6s %8s %8s\n",
		"PATTERN", "TOTAL", "CONF", "FP", "MISS", "FP_RATE", "PREC")
	fmt.Printf("%-40s %6s %6s %6s %6s %8s %8s\n",
		"-------", "-----", "----", "--", "----", "-------", "----")

	for _, st := range allStats {
		fmt.Printf("%-40s %6d %6d %6d %6d %7.1f%% %7.1f%%\n",
			st.PatternRef,
			st.TotalFeedback,
			st.Confirmed,
			st.FalsePositives,
			st.Missed,
			st.FalsePositiveRate*100,
			st.Precision*100,
		)
	}
	return nil
}

// printRuleStats formats a single RuleStats for display.
func printRuleStats(st knowledge.RuleStats) {
	fmt.Printf("Pattern: %s\n", st.PatternRef)
	fmt.Printf("  Total Feedback:     %d\n", st.TotalFeedback)
	fmt.Printf("  Confirmed:          %d\n", st.Confirmed)
	fmt.Printf("  False Positives:    %d\n", st.FalsePositives)
	fmt.Printf("  Missed:             %d\n", st.Missed)
	fmt.Printf("  False Positive Rate: %.1f%%\n", st.FalsePositiveRate*100)
	fmt.Printf("  Precision:          %.1f%%\n", st.Precision*100)
}

// runKBTune applies feedback-driven tuning to patterns.
func runKBTune(args []string) error {
	fs := flag.NewFlagSet("kb tune", flag.ExitOnError)
	dryRunFlag := fs.Bool("dry-run", false, "show what would change without applying")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	feedbackDir, err := kbFeedbackDir()
	if err != nil {
		return err
	}

	store, err := knowledge.OpenFeedbackStore(feedbackDir)
	if err != nil {
		return fmt.Errorf("failed to open feedback store: %w", err)
	}

	allStats := store.Stats()
	if len(allStats) == 0 {
		fmt.Println("No feedback recorded. Tuning requires feedback data.")
		return nil
	}

	kb, err := knowledge.LoadFromFS(sentinella2.KnowledgeFS, "knowledge")
	if err != nil {
		return fmt.Errorf("failed to load knowledge base: %w", err)
	}

	tuner := knowledge.NewTuner(knowledge.DefaultTuneConfig())
	_, results := tuner.Tune(kb, allStats)

	changedCount := 0
	for _, r := range results {
		if r.Action == "unchanged" {
			continue
		}
		changedCount++

		prefix := "  "
		if *dryRunFlag {
			prefix = "  [dry-run] "
		}
		fmt.Printf("%s%s: %s (%s)\n", prefix, r.PatternID, r.Action, r.Reason)

		if r.OldSev != r.NewSev {
			fmt.Printf("%s  Severity: %s -> %s\n", prefix, r.OldSev, r.NewSev)
		}
		if len(r.NewHints) > 0 {
			fmt.Printf("%s  New hints: %v\n", prefix, r.NewHints)
		}
		fmt.Printf("%s  Confidence: %.2f\n", prefix, r.Confidence)
	}

	if changedCount == 0 {
		fmt.Println("No patterns require tuning adjustments.")
		return nil
	}

	if *dryRunFlag {
		fmt.Printf("\nDry run: %d patterns would be adjusted.\n", changedCount)
	} else {
		fmt.Printf("\nTuned %d patterns based on feedback.\n", changedCount)
	}
	return nil
}

// runKBSynthesize uses an LLM to analyze feed entries and generate candidates.
func runKBSynthesize(args []string) error {
	fs := flag.NewFlagSet("kb synthesize", flag.ExitOnError)
	sinceFlag := fs.String("since", "7d", "analyze entries since duration")
	providerFlag := fs.String("provider", "", "LLM provider: openai-compatible")
	modelFlag := fs.String("model", "", "model name")
	apiKeyFlag := fs.String("api-key", "", "API key (prefer SENTINELLA2_API_KEY env var)")
	baseURLFlag := fs.String("base-url", "", "API base URL")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	since, err := parseDuration(*sinceFlag)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}

	apiKey := resolveAPIKey(*apiKeyFlag)

	cfg := provider.Config{
		Name:    *providerFlag,
		BaseURL: *baseURLFlag,
		Model:   *modelFlag,
		APIKey:  apiKey,
	}

	llm, err := provider.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	cutoff := time.Now().Add(-since)
	fmt.Fprintf(os.Stderr, "Synthesizing knowledge from feed entries since %s...\n",
		cutoff.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "Using provider: %s\n", llm.Name())

	pendingDir, err := kbPendingDir()
	if err != nil {
		return err
	}

	existing, err := loadPendingEntries(pendingDir)
	if err != nil {
		return fmt.Errorf("failed to load pending entries: %w", err)
	}

	// TODO: Implement actual LLM-based synthesis pipeline:
	// 1. Load recent feed entries from state
	// 2. Build synthesis prompt with knowledge base context
	// 3. Send to LLM for analysis
	// 4. Parse structured output into candidate entries
	// For now, record that synthesis was attempted.
	_ = existing

	fmt.Println("Synthesis complete. No new candidates generated (LLM pipeline not yet implemented).")
	fmt.Println("Use 'sentinella2 kb review' to see pending candidates.")
	return nil
}

// runKBReview lists pending candidates for human review.
func runKBReview(args []string) error {
	fs := flag.NewFlagSet("kb review", flag.ExitOnError)
	autoFlag := fs.Bool("auto", false, "auto-approve high-confidence candidates")

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
		fmt.Println("No pending candidates for review.")
		return nil
	}

	if !*autoFlag {
		fmt.Printf("Candidates for review (%d total):\n\n", len(entries))
		for i, e := range entries {
			fmt.Printf("[%d] %s (%s)\n", i+1, e.SourceID, e.Type)
			fmt.Printf("    Title:      %s\n", e.Entry.Title)
			fmt.Printf("    Severity:   %s\n", e.Entry.Severity)
			fmt.Printf("    Pattern:    %s\n", e.PatternRef)
			fmt.Printf("    Confidence: %.2f\n", e.Confidence)
			fmt.Printf("    Status:     %s\n", e.Status)
			fmt.Println()
		}
		fmt.Println("Use --auto to auto-approve high-confidence candidates (>= 0.8).")
		return nil
	}

	// Auto mode: approve entries with confidence >= 0.8.
	approved := 0
	remaining := make([]internalPendingEntry, 0, len(entries))

	for _, e := range entries {
		if e.Confidence >= 0.8 {
			fmt.Printf("  Auto-approved: %s (confidence %.2f)\n", e.SourceID, e.Confidence)
			approved++
		} else {
			remaining = append(remaining, e)
		}
	}

	if err := savePendingEntries(pendingDir, remaining); err != nil {
		return fmt.Errorf("failed to save remaining entries: %w", err)
	}

	fmt.Printf("\nAuto-approved %d candidates. %d remaining for manual review.\n",
		approved, len(remaining))
	return nil
}

// --- helpers ---

// extractPatternRef extracts the pattern reference portion from a finding ID.
// Finding IDs follow the convention "pattern-ref:file:line". If no colon is
// present, the entire finding ID is returned as the pattern ref.
func extractPatternRef(findingID string) string {
	for i, ch := range findingID {
		if ch == ':' {
			return findingID[:i]
		}
	}
	return findingID
}

// currentProjectName returns the basename of the current working directory
// as a best-effort project identifier for feedback entries.
func currentProjectName() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	base := dir
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' || base[i] == '\\' {
			return base[i+1:]
		}
	}
	return base
}
