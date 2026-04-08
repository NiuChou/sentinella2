package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// runMemory dispatches memory subcommands.
func runMemory(args []string) error {
	if len(args) < 1 {
		printMemoryUsage()
		return fmt.Errorf("usage: sentinella2 memory <subcommand>")
	}

	switch args[0] {
	case "list":
		return runMemoryList(args[1:])
	case "add":
		return runMemoryAdd(args[1:])
	case "remove":
		return runMemoryRemove(args[1:])
	case "validate":
		return runMemoryValidate(args[1:])
	default:
		printMemoryUsage()
		return fmt.Errorf("unknown memory subcommand: %s", args[0])
	}
}

// printMemoryUsage prints the memory subcommand help text.
func printMemoryUsage() {
	fmt.Fprintf(os.Stderr, `sentinella2 memory - Context memory management

Subcommands:
  list      List all memories grouped by scope
  add       Add a memory declaration
  remove    Remove a memory by index
  validate  Validate memory file (check referenced files/patterns)

Examples:
  sentinella2 memory list
  sentinella2 memory add --scope project "Auth is handled at API Gateway"
  sentinella2 memory add --scope scanner --scanner S7 "NestJS @UseGuards applied globally"
  sentinella2 memory add --scope pattern --match "**/*.controller.ts" "All controllers extend BaseController"
  sentinella2 memory remove 1
  sentinella2 memory validate
`)
}

// resolveMemoryPath returns the memories.yaml path for the current directory.
func resolveMemoryPath() string {
	cwd, err := os.Getwd()
	if err != nil {
		return knowledge.DefaultMemoryPath(".")
	}
	return knowledge.DefaultMemoryPath(cwd)
}

// runMemoryList lists all memories grouped by scope.
func runMemoryList(args []string) error {
	fs := flag.NewFlagSet("memory list", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	store, err := knowledge.OpenMemoryStore(resolveMemoryPath())
	if err != nil {
		return fmt.Errorf("open memory store: %w", err)
	}

	memories := store.All()
	if len(memories) == 0 {
		fmt.Println("No memories declared.")
		fmt.Println("Use 'sentinella2 memory add' to add project context.")
		return nil
	}

	// Group by scope for display.
	byScope := map[knowledge.MemoryScope][]indexedMemory{}
	for i, m := range memories {
		byScope[m.Scope] = append(byScope[m.Scope], indexedMemory{index: i, mem: m})
	}

	fmt.Printf("Memories (%d total)\n\n", len(memories))

	if items, ok := byScope[knowledge.ScopeProject]; ok {
		fmt.Println("Project-scoped:")
		for _, item := range items {
			fmt.Printf("  %s %s\n", knowledge.MemoryIndexLabel(item.index), item.mem.Text)
		}
		fmt.Println()
	}

	if items, ok := byScope[knowledge.ScopeScanner]; ok {
		fmt.Println("Scanner-scoped:")
		for _, item := range items {
			fmt.Printf("  %s [%s] %s\n", knowledge.MemoryIndexLabel(item.index), item.mem.Scanner, item.mem.Text)
		}
		fmt.Println()
	}

	if items, ok := byScope[knowledge.ScopePattern]; ok {
		fmt.Println("Pattern-scoped:")
		for _, item := range items {
			fmt.Printf("  %s match=%s  %s\n", knowledge.MemoryIndexLabel(item.index), item.mem.FileMatch, item.mem.Text)
		}
		fmt.Println()
	}

	return nil
}

// indexedMemory pairs a zero-based index with a Memory for display purposes.
type indexedMemory struct {
	index int
	mem   knowledge.Memory
}

// runMemoryAdd adds a new memory declaration to the store.
func runMemoryAdd(args []string) error {
	fs := flag.NewFlagSet("memory add", flag.ExitOnError)
	scopeFlag := fs.String("scope", "project", "memory scope: project, scanner, pattern")
	scannerFlag := fs.String("scanner", "", "scanner ID (required when --scope=scanner)")
	matchFlag := fs.String("match", "", "file glob pattern (required when --scope=pattern)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 memory add [--scope project|scanner|pattern] [--scanner ID] [--match GLOB] <text>")
	}

	text := fs.Arg(0)
	scope := knowledge.MemoryScope(*scopeFlag)

	mem := knowledge.Memory{
		Scope:     scope,
		Scanner:   *scannerFlag,
		FileMatch: *matchFlag,
		Text:      text,
	}

	store, err := knowledge.OpenMemoryStore(resolveMemoryPath())
	if err != nil {
		return fmt.Errorf("open memory store: %w", err)
	}

	if err := store.Add(mem); err != nil {
		return fmt.Errorf("add memory: %w", err)
	}

	fmt.Printf("Added %s memory: %s\n", scope, text)
	return nil
}

// runMemoryRemove removes a memory by its 1-based display index.
func runMemoryRemove(args []string) error {
	fs := flag.NewFlagSet("memory remove", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sentinella2 memory remove <index>")
	}

	// Accept 1-based index (as displayed by memory list).
	displayIndex, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid index %q: must be a number", fs.Arg(0))
	}
	if displayIndex < 1 {
		return fmt.Errorf("index must be >= 1")
	}
	zeroIndex := displayIndex - 1

	store, err := knowledge.OpenMemoryStore(resolveMemoryPath())
	if err != nil {
		return fmt.Errorf("open memory store: %w", err)
	}

	memories := store.All()
	if zeroIndex >= len(memories) {
		return fmt.Errorf("index %d out of range; store has %d memories", displayIndex, len(memories))
	}

	removed := memories[zeroIndex]
	if err := store.Remove(zeroIndex); err != nil {
		return fmt.Errorf("remove memory: %w", err)
	}

	fmt.Printf("Removed memory [%d]: %s\n", displayIndex, removed.Text)
	return nil
}

// runMemoryValidate performs basic validation of the memory store.
func runMemoryValidate(args []string) error {
	fs := flag.NewFlagSet("memory validate", flag.ExitOnError)
	dirFlag := fs.String("dir", ".", "project root directory to resolve file patterns against")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	store, err := knowledge.OpenMemoryStore(resolveMemoryPath())
	if err != nil {
		return fmt.Errorf("open memory store: %w", err)
	}

	memories := store.All()
	if len(memories) == 0 {
		fmt.Println("Memory store is empty. Nothing to validate.")
		return nil
	}

	issues := 0
	for i, m := range memories {
		label := knowledge.MemoryIndexLabel(i)
		switch m.Scope {
		case knowledge.ScopeScanner:
			if m.Scanner == "" {
				fmt.Printf("  %s WARN: scanner-scoped memory has no scanner ID\n", label)
				issues++
			}
		case knowledge.ScopePattern:
			if m.FileMatch == "" {
				fmt.Printf("  %s WARN: pattern-scoped memory has no match glob\n", label)
				issues++
			} else {
				// Check if the glob matches anything in the project directory.
				matched, err := globMatchesAny(*dirFlag, m.FileMatch)
				if err != nil {
					fmt.Printf("  %s WARN: glob %q error: %v\n", label, m.FileMatch, err)
					issues++
				} else if !matched {
					fmt.Printf("  %s INFO: glob %q matches no files in %s\n", label, m.FileMatch, *dirFlag)
				}
			}
		}
	}

	if issues > 0 {
		return fmt.Errorf("validation found %d issue(s)", issues)
	}

	fmt.Printf("Memory store valid (%d memories).\n", len(memories))
	return nil
}

// globMatchesAny returns true if the glob pattern matches at least one file
// under rootDir. It uses filepath.Walk for simplicity; large trees are not
// a concern here since this is a developer-time validation command.
func globMatchesAny(rootDir, pattern string) (bool, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return false, fmt.Errorf("resolve root dir: %w", err)
	}

	found := false
	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(absRoot, path)
		if err != nil {
			return nil
		}
		matched, matchErr := filepath.Match(pattern, rel)
		if matchErr != nil {
			return matchErr
		}
		if matched {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("walk %s: %w", rootDir, err)
	}
	return found, nil
}
