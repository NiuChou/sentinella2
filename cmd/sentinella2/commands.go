package main

import (
	"context"
	"fmt"
	"os"
	"time"

	sentinella2 "github.com/perseworks/sentinella2"
	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/provider"
	"github.com/perseworks/sentinella2/pkg/report"
	"github.com/perseworks/sentinella2/pkg/scan"
)

// executeScan runs a Tier 1 pattern-based scan and writes results to stdout.
func executeScan(targetPath string, format report.Format) error {
	if err := validatePath(targetPath); err != nil {
		return err
	}

	kb, err := loadKnowledge()
	if err != nil {
		return err
	}

	scanner := scan.New(scan.WithKnowledge(kb))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := scanner.Scan(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	reporter := report.New(format)
	return reporter.Report(os.Stdout, result)
}

// executeAudit runs a Tier 1 scan followed by Tier 2+ LLM-based deep audit.
func executeAudit(targetPath string, format report.Format, cfg provider.Config) error {
	if err := validatePath(targetPath); err != nil {
		return err
	}

	kb, err := loadKnowledge()
	if err != nil {
		return err
	}

	llm, err := provider.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Using provider: %s\n", llm.Name())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Phase 1: Run Tier 1 scan.
	scanner := scan.New(scan.WithKnowledge(kb))
	result, err := scanner.Scan(ctx, targetPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Phase 2: Send findings to LLM for deep analysis.
	// TODO: Implement LLM audit pipeline that sends code context and findings
	// to the provider for Tier 2+ analysis.
	_ = llm

	reporter := report.New(format)
	return reporter.Report(os.Stdout, result)
}

// executeCheckLayers assesses defense-in-depth layers for the given path.
func executeCheckLayers(targetPath string, format report.Format) error {
	if err := validatePath(targetPath); err != nil {
		return err
	}

	kb, err := loadKnowledge()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	layerResult, err := scan.ScanDefenseLayers(ctx, targetPath, kb)
	if err != nil {
		return fmt.Errorf("layer assessment failed: %w", err)
	}

	reporter := report.New(format)
	return reporter.ReportLayers(os.Stdout, layerResult)
}

// loadKnowledge loads the embedded knowledge base.
func loadKnowledge() (knowledge.KnowledgeBase, error) {
	kb, err := knowledge.LoadFromFS(sentinella2.KnowledgeFS, "knowledge")
	if err != nil {
		return knowledge.KnowledgeBase{}, fmt.Errorf("failed to load knowledge base: %w", err)
	}
	return kb, nil
}

func validatePath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot access path %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path %q is not a directory", path)
	}
	return nil
}
