// Command sentinella2 is the CLI entry point for the sentinella2 security
// audit engine. It provides scan, audit, check-layers, init, and version
// subcommands.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/perseworks/sentinella2/pkg/provider"
	"github.com/perseworks/sentinella2/pkg/report"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "check-layers":
		err = runCheckLayers(os.Args[2:])
	case "kb":
		err = runKB(os.Args[2:])
	case "memory":
		err = runMemory(os.Args[2:])
	case "triage":
		err = runTriage(os.Args[2:])
	case "learn":
		err = runLearn(os.Args[2:])
	case "init":
		err = runInit()
	case "version":
		fmt.Printf("sentinella2 v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	formatFlag := fs.String("format", "text", "output format: text, json, markdown")
	_ = fs.Bool("changed-only", false, "scan only changed files (git diff)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 scan <path> [--format text|json|markdown]")
	}

	format, err := report.ParseFormat(*formatFlag)
	if err != nil {
		return err
	}

	targetPath := fs.Arg(0)
	return executeScan(targetPath, format)
}

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	formatFlag := fs.String("format", "text", "output format: text, json, markdown")
	providerFlag := fs.String("provider", "", "LLM provider: openai-compatible")
	modelFlag := fs.String("model", "", "model name (e.g., claude-sonnet-4-20250514)")
	apiKeyFileFlag := fs.String("api-key-file", "", "path to file containing API key (prefer SENTINELLA2_API_KEY env var)")
	baseURLFlag := fs.String("base-url", "", "API base URL")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 audit <path> --provider <name> --model <model>")
	}

	format, err := report.ParseFormat(*formatFlag)
	if err != nil {
		return err
	}

	apiKey, err := resolveAPIKey(*apiKeyFileFlag)
	if err != nil {
		return err
	}

	cfg := provider.Config{
		Name:    *providerFlag,
		BaseURL: *baseURLFlag,
		Model:   *modelFlag,
		APIKey:  apiKey,
	}

	targetPath := fs.Arg(0)
	return executeAudit(targetPath, format, cfg)
}

func runCheckLayers(args []string) error {
	fs := flag.NewFlagSet("check-layers", flag.ExitOnError)
	formatFlag := fs.String("format", "text", "output format: text, json, markdown")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 check-layers <path> [--format text|json|markdown]")
	}

	format, err := report.ParseFormat(*formatFlag)
	if err != nil {
		return err
	}

	targetPath := fs.Arg(0)
	return executeCheckLayers(targetPath, format)
}

func runInit() error {
	targetDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}
	configPath := filepath.Join(targetDir, ".sentinella2.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("%s already exists", configPath)
	}
	defaultConfig := `# sentinella2 configuration
scan:
  exclude: ["vendor/**", "node_modules/**"]

# audit:
#   provider: "openai-compatible"
#   base_url: "http://localhost:11434/v1"
#   model: "llama3"
`
	if err := os.WriteFile(configPath, []byte(defaultConfig), 0o600); err != nil {
		return fmt.Errorf("creating config: %w", err)
	}
	fmt.Printf("Created %s\n", configPath)
	return nil
}

// resolveAPIKey returns the API key from the environment variable, falling
// back to reading from a file. The key is never accepted as a CLI flag to
// avoid exposing secrets in the process list.
func resolveAPIKey(keyFilePath string) (string, error) {
	if envKey := os.Getenv("SENTINELLA2_API_KEY"); envKey != "" {
		return envKey, nil
	}
	if keyFilePath != "" {
		data, err := os.ReadFile(keyFilePath)
		if err != nil {
			return "", fmt.Errorf("reading api-key-file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil // no key = noop provider
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `sentinella2 - Security audit knowledge base + engine

Usage:
  sentinella2 <command> [options]

Commands:
  scan          Scan code for vulnerability patterns (Tier 1, no LLM required)
  audit         Deep audit with LLM analysis (Tier 2+, requires provider config)
  check-layers  Assess defense-in-depth layers
  kb            Knowledge base management (update, feedback, tune, synthesize)
  memory        Context memory management (list, add, remove, validate)
  triage        Interactively label uncertain findings to improve calibration
  learn         Analyze labeled findings and suggest rules from patterns
  init          Create default configuration file
  version       Print version
  help          Show this help

Examples:
  sentinella2 scan ./src --format json
  sentinella2 audit ./src --provider openai-compatible --model gpt-4o --base-url https://api.openai.com/v1
  sentinella2 check-layers ./infrastructure --format markdown
  sentinella2 triage ./src --batch 20
  sentinella2 kb update --since 7d
  sentinella2 kb feedback mark finding-123 false_positive --reason "test code"
  sentinella2 kb tune --dry-run
  sentinella2 memory list
  sentinella2 memory add --scope project "Auth handled at API Gateway"
  sentinella2 memory add --scope scanner --scanner S7 "NestJS @UseGuards applied globally"
  sentinella2 learn --feedback-dir .sentinella2/feedback
`)

}
