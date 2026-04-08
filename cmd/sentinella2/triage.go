package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	sentinella2 "github.com/perseworks/sentinella2"
	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/scan"
)

// runTriage implements the triage command: interactively label the most
// uncertain findings to improve calibration.
//
// Usage:
//
//	sentinella2 triage <path> [--batch N] [--format text|json]
func runTriage(args []string) error {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	batchFlag := fs.Int("batch", 20, "number of findings to label in this session")
	formatFlag := fs.String("format", "text", "output format: text|json (affects post-triage summary only)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse triage flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 triage <path> [--batch N]")
	}

	targetPath := fs.Arg(0)
	_ = *formatFlag // reserved for future structured summary output

	if err := validatePath(targetPath); err != nil {
		return err
	}

	// Step 1: Load knowledge base and run scan.
	kb, err := loadKnowledge()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner := scan.New(scan.WithKnowledge(kb))
	result, err := scanner.Scan(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	findings := result.Findings()
	if len(findings) == 0 {
		fmt.Println("No findings to triage.")
		return nil
	}

	// Step 2: Open state and calibration stores.
	homeDir, err := sentinellaHomeDir()
	if err != nil {
		return err
	}

	statePath := filepath.Join(homeDir, "state.json")
	stateStore, err := knowledge.OpenStateStore(statePath)
	if err != nil {
		return fmt.Errorf("failed to open state store: %w", err)
	}

	calibPath := filepath.Join(homeDir, "calibration.json")
	calibStore, err := knowledge.OpenCalibrationStore(calibPath, sentinella2.KnowledgeFS)
	if err != nil {
		return fmt.Errorf("failed to open calibration store: %w", err)
	}

	// Step 3: Choose sort strategy.
	// Cold start (> 80% uncovered buckets): guided labeling maximises learning value.
	// Hot start: pure uncertainty sampling (existing behaviour).
	isCold := scan.IsColdStart(findings, calibStore, 5)
	var sortedFindings []scan.Finding
	var priorities []scan.TriagePriority

	if isCold {
		fmt.Println("Cold start detected. Using guided labeling for maximum learning value.")
		priorities = scan.ComputeTriagePriorities(findings, calibStore, scan.DefaultTriageConfig())
		sortedFindings = make([]scan.Finding, len(priorities))
		for i, p := range priorities {
			sortedFindings[i] = p.Finding
		}
	} else {
		sortedFindings = sortByUncertainty(findings)
	}

	batchSize := *batchFlag
	if batchSize > len(sortedFindings) {
		batchSize = len(sortedFindings)
	}
	batch := sortedFindings[:batchSize]
	var batchPriorities []scan.TriagePriority
	if len(priorities) > 0 && batchSize <= len(priorities) {
		batchPriorities = priorities[:batchSize]
	}

	// Step 4: Handle Ctrl+C gracefully.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	reader := bufio.NewReader(os.Stdin)

	labeled := 0
	buckets := make(map[string]bool)

	if isCold {
		fmt.Printf("\nTriaging %d/%d findings (guided labeling — cold start)\n\n", batchSize, len(sortedFindings))
	} else {
		fmt.Printf("\nTriaging %d/%d findings (sorted by uncertainty)\n\n", batchSize, len(sortedFindings))
	}

	for i, f := range batch {
		// Check for interrupt between findings.
		select {
		case <-sigCh:
			fmt.Println("\nInterrupted.")
			goto done
		default:
		}

		var prio *scan.TriagePriority
		if i < len(batchPriorities) {
			p := batchPriorities[i]
			prio = &p
		}

		verdict, err := promptFindingWithPriority(reader, i+1, batchSize, f, result.TargetDir(), prio)
		if err != nil {
			return err
		}
		if verdict == "" {
			// Skipped.
			continue
		}

		// Step 5: Update state store.
		stableID := f.StableID(result.TargetDir())
		state := knowledge.FindingState{
			Status:     verdictToStatus(knowledge.Verdict(verdict)),
			PatternRef: f.PatternRef,
			File:       f.File,
			FirstSeen:  time.Now().UTC(),
			LabeledAt:  time.Now().UTC(),
			LabeledBy:  "triage",
		}
		if existing, ok := stateStore.Get(stableID); ok {
			state.FirstSeen = existing.FirstSeen
		}
		if err := stateStore.Update(stableID, state); err != nil {
			return fmt.Errorf("failed to update state for %s: %w", stableID, err)
		}

		// Update calibration store.
		fileGlob := fileGlobFromPath(f.File)
		calibStore.RecordVerdict(f.PatternRef, fileGlob, knowledge.Verdict(verdict))

		buckets[f.PatternRef+":"+fileGlob] = true
		labeled++
	}

done:
	if err := stateStore.Save(); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}
	if err := calibStore.Save(); err != nil {
		return fmt.Errorf("failed to save calibration: %w", err)
	}

	fmt.Printf("\nLabeled %d findings. Updated calibration for %d buckets.\n",
		labeled, len(buckets))
	return nil
}

// sortByUncertainty returns findings sorted by |confidence - 0.5| ascending
// so that the most uncertain findings (closest to 0.5) come first.
// The original slice is not modified.
func sortByUncertainty(findings []scan.Finding) []scan.Finding {
	out := make([]scan.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		ui := math.Abs(out[i].Confidence - 0.5)
		uj := math.Abs(out[j].Confidence - 0.5)
		return ui < uj
	})
	return out
}

// promptFindingWithPriority prints a finding prompt (with optional guided priority
// info) and reads the user's verdict. Returns "" for skip and an error only on
// I/O failure.
func promptFindingWithPriority(
	reader *bufio.Reader,
	idx, total int,
	f scan.Finding,
	rootDir string,
	prio *scan.TriagePriority,
) (string, error) {
	stableID := f.StableID(rootDir)

	fmt.Printf("[%d/%d] %s (confidence: %.1f%%)\n",
		idx, total, stableID, f.Confidence*100)
	fmt.Printf("  File: %s:%d\n", f.File, f.Line)
	if f.Message != "" {
		fmt.Printf("  Match: %q\n", truncate(f.Message, 80))
	}
	if prio != nil {
		fmt.Printf("  Priority: %.2f  Reason: %s  Impact: %d similar finding(s)\n",
			prio.Priority, prio.Reason, prio.Impact)
	}
	fmt.Print("  [C]onfirmed  [F]alse positive  [A]ccepted  [S]kip? > ")

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	line = strings.TrimSpace(strings.ToLower(line))

	switch line {
	case "c", "confirmed":
		return string(knowledge.VerdictConfirmed), nil
	case "f", "false_positive", "false positive", "fp":
		return string(knowledge.VerdictFalsePositive), nil
	case "a", "accepted":
		return string(knowledge.VerdictAccepted), nil
	default:
		// Any other input, including "s" or empty, counts as skip.
		return "", nil
	}
}

// verdictToStatus converts a Verdict to the corresponding FindingStatus.
func verdictToStatus(v knowledge.Verdict) knowledge.FindingStatus {
	switch v {
	case knowledge.VerdictConfirmed:
		return knowledge.StatusConfirmed
	case knowledge.VerdictFalsePositive:
		return knowledge.StatusFalsePositive
	case knowledge.VerdictAccepted:
		return knowledge.StatusAccepted
	case knowledge.VerdictFixed:
		return knowledge.StatusFixed
	default:
		return knowledge.StatusOpen
	}
}

// fileGlobFromPath extracts a file glob pattern (e.g. "*.controller.ts") from
// a full file path using the same logic as the calibration store's fileGlobFor.
func fileGlobFromPath(path string) string {
	base := filepath.Base(path)
	for i, ch := range base {
		if ch == '.' && i > 0 {
			return "*" + base[i:]
		}
	}
	return "*"
}

// truncate clips s to at most maxLen characters, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
