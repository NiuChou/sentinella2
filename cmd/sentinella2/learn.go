package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// runLearn runs the learn command, which mines feedback for false positive
// patterns and interactively suggests improvements.
func runLearn(args []string) error {
	fs := flag.NewFlagSet("learn", flag.ExitOnError)
	feedbackDirFlag := fs.String("feedback-dir", "", "path to feedback directory (default: .sentinella2/feedback)")
	minFPRateFlag := fs.Float64("min-fp-rate", 0.8, "minimum FP rate to report (0.0-1.0)")
	minSamplesFlag := fs.Int("min-samples", 5, "minimum sample count per cluster")
	calibrationPathFlag := fs.String("calibration-path", "", "path to calibration.json (default: .sentinella2/calibration.json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("learn: failed to parse flags: %w", err)
	}

	feedbackDir, err := resolveFeedbackDir(*feedbackDirFlag)
	if err != nil {
		return err
	}

	store, err := knowledge.OpenFeedbackStore(feedbackDir)
	if err != nil {
		return fmt.Errorf("learn: failed to open feedback store: %w", err)
	}

	entries := store.Entries()
	if len(entries) == 0 {
		fmt.Println("No feedback recorded yet. Use 'sentinella2 kb feedback mark' to record findings.")
		return nil
	}

	fmt.Printf("Analyzing %d labeled findings...\n\n", len(entries))

	cfg := knowledge.MinerConfig{
		MinFPRate:  *minFPRateFlag,
		MinSamples: *minSamplesFlag,
	}
	miner := knowledge.NewMiner(cfg)
	result := miner.Mine(entries)

	// Detect bucket splits (independent of miner cluster results)
	calibrationPath := resolveCalibrationPath(*calibrationPathFlag)
	if err := runSplitDetection(entries, calibrationPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: split detection failed: %v\n", err)
	}

	if len(result.Clusters) == 0 {
		fmt.Println("No false positive patterns detected with current thresholds.")
		fmt.Printf("  (analyzed %d entries, min FP rate: %.0f%%, min samples: %d)\n",
			result.TotalAnalyzed, cfg.MinFPRate*100, cfg.MinSamples)
		return nil
	}

	memoryPath := resolveLearnMemoryPath()
	memStore, err := knowledge.OpenMemoryStore(memoryPath)
	if err != nil {
		return fmt.Errorf("learn: failed to open memory store: %w", err)
	}

	applied, skipped := 0, 0
	reader := bufio.NewReader(os.Stdin)

	for i, action := range result.Suggested {
		if action.Type != knowledge.SuggestMemory {
			continue
		}

		c := action.Cluster
		fmt.Printf("Pattern #%d: %s on %s — %.0f%% FP (%d/%d)\n",
			i+1, c.PatternRef, c.FilePattern, c.FPRate*100, c.FPCount, c.TotalCount)
		fmt.Printf("  Suggested: Add memory %q\n", action.MemoryText)
		fmt.Print("  [A]pply  [S]kip? > ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("learn: failed to read input: %w", err)
		}
		choice = strings.TrimSpace(strings.ToLower(choice))

		switch choice {
		case "a", "apply", "":
			mem := knowledge.Memory{
				Scope: knowledge.ScopeProject,
				Text:  action.MemoryText,
			}
			if err := memStore.Add(mem); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: failed to save memory: %v\n", err)
				skipped++
			} else {
				fmt.Printf("  Applied memory note.\n")
				applied++
			}
		default:
			fmt.Printf("  Skipped.\n")
			skipped++
		}
		fmt.Println()
	}

	fmt.Printf("Summary: %d applied, %d skipped.\n", applied, skipped)
	if applied > 0 {
		fmt.Printf("Memory notes saved to: %s\n", memoryPath)
	}
	return nil
}

// resolveFeedbackDir returns the feedback directory, falling back to
// .sentinella2/feedback in current directory if flag is empty.
func resolveFeedbackDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	dir := filepath.Join(".sentinella2", "feedback")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("learn: failed to create feedback directory: %w", err)
	}
	return dir, nil
}

// resolveLearnMemoryPath returns the path for the memory store used by learn.
func resolveLearnMemoryPath() string {
	return filepath.Join(".sentinella2", "memories.yaml")
}

// resolveCalibrationPath returns the calibration.json path, falling back to
// .sentinella2/calibration.json if flag is empty.
func resolveCalibrationPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return filepath.Join(".sentinella2", "calibration.json")
}

// runSplitDetection detects and optionally applies bucket splits interactively.
func runSplitDetection(entries []knowledge.FeedbackEntry, calibrationPath string) error {
	cs, err := knowledge.OpenCalibrationStore(calibrationPath, nil)
	if err != nil {
		return fmt.Errorf("open calibration store: %w", err)
	}

	splits := cs.DetectSplits(entries, 0.3)
	if len(splits) == 0 {
		return nil
	}

	fmt.Printf("\nDetecting bucket splits...\n")
	for _, s := range splits {
		fmt.Printf("  %s (conf=%.0f%%)\n", s.ParentKey, s.ParentConf*100)
		fmt.Printf("    -> %s diverges: conf=%.0f%% (delta=%.0f%%)\n",
			s.ChildKey.FileGlob(), s.ChildConf*100, s.Divergence*100)
	}
	fmt.Print("  Apply splits? [Y/n] > ")

	reader := bufio.NewReader(os.Stdin)
	choice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	choice = strings.TrimSpace(strings.ToLower(choice))

	if choice == "n" || choice == "no" {
		fmt.Println("  Splits skipped.")
		return nil
	}

	applied := 0
	for _, s := range splits {
		if err := cs.ApplySplit(s, entries); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: failed to apply split %s: %v\n", s.ChildKey, err)
			continue
		}
		fmt.Printf("  Applied split: %s\n", s.ChildKey)
		applied++
	}
	if applied > 0 {
		if err := cs.Save(); err != nil {
			return fmt.Errorf("save calibration: %w", err)
		}
		fmt.Printf("  %d split(s) applied and saved to: %s\n", applied, calibrationPath)
	}
	return nil
}
