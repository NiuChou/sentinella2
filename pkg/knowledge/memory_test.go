package knowledge

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// tempDir creates a temporary directory and registers cleanup with t.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sentinella2-memory-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// memoryPath returns the default memory path inside dir.
func memoryPath(dir string) string {
	return filepath.Join(dir, ".sentinella2", "memories.yaml")
}

// TestMemoryStore_OpenCreate verifies that opening a non-existent store
// succeeds and creates the file on first Save.
func TestMemoryStore_OpenCreate(t *testing.T) {
	dir := tempDir(t)
	path := memoryPath(dir)

	store, err := OpenMemoryStore(path)
	if err != nil {
		t.Fatalf("OpenMemoryStore: unexpected error: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}

	// File should not exist yet.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file to not exist before first save, got err=%v", err)
	}

	// Save creates the file.
	if err := store.Save(); err != nil {
		t.Fatalf("Save: unexpected error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist after save: %v", err)
	}
}

// TestMemoryStore_LoadExisting verifies that an existing memories.yaml with
// all three scopes is loaded correctly.
func TestMemoryStore_LoadExisting(t *testing.T) {
	dir := tempDir(t)
	path := memoryPath(dir)

	// Write a hand-crafted YAML fixture.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fixture := `schema_version: "1.0"
kind: memories
project:
  - "Auth at API Gateway"
  - "Tenant isolation via Supabase RLS"
scanners:
  S7:
    - "NestJS @UseGuards globally applied"
  S12:
    - "Schema-qualified table names"
patterns:
  - match: "**/*.controller.ts"
    memory: "All controllers extend BaseController"
`
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	store, err := OpenMemoryStore(path)
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}

	all := store.All()
	if len(all) != 5 {
		t.Errorf("expected 5 memories, got %d: %+v", len(all), all)
	}

	// Verify project-scoped items.
	var projectTexts []string
	for _, m := range all {
		if m.Scope == ScopeProject {
			projectTexts = append(projectTexts, m.Text)
		}
	}
	wantProject := []string{"Auth at API Gateway", "Tenant isolation via Supabase RLS"}
	if !reflect.DeepEqual(projectTexts, wantProject) {
		t.Errorf("project texts: got %v, want %v", projectTexts, wantProject)
	}

	// Verify scanner-scoped items.
	s7 := store.ForScanner("S7")
	var s7Texts []string
	for _, m := range s7 {
		if m.Scope == ScopeScanner {
			s7Texts = append(s7Texts, m.Text)
		}
	}
	if len(s7Texts) != 1 || s7Texts[0] != "NestJS @UseGuards globally applied" {
		t.Errorf("S7 scanner texts: got %v", s7Texts)
	}

	// Verify pattern-scoped items.
	for _, m := range all {
		if m.Scope == ScopePattern {
			if m.FileMatch != "**/*.controller.ts" {
				t.Errorf("pattern match: got %q, want **/*.controller.ts", m.FileMatch)
			}
			if m.Text != "All controllers extend BaseController" {
				t.Errorf("pattern text: got %q", m.Text)
			}
		}
	}
}

// TestMemoryStore_Add verifies that memories can be added at each scope level.
func TestMemoryStore_Add(t *testing.T) {
	tests := []struct {
		name    string
		mem     Memory
		wantErr bool
	}{
		{
			name: "project scope",
			mem:  Memory{Scope: ScopeProject, Text: "Auth at gateway"},
		},
		{
			name: "scanner scope",
			mem:  Memory{Scope: ScopeScanner, Scanner: "S7", Text: "Guards applied globally"},
		},
		{
			name: "pattern scope",
			mem:  Memory{Scope: ScopePattern, FileMatch: "**/*.ts", Text: "TypeScript controllers"},
		},
		{
			name:    "empty text rejected",
			mem:     Memory{Scope: ScopeProject, Text: ""},
			wantErr: true,
		},
		{
			name:    "scanner scope missing scanner ID",
			mem:     Memory{Scope: ScopeScanner, Text: "some memory"},
			wantErr: true,
		},
		{
			name:    "pattern scope missing match glob",
			mem:     Memory{Scope: ScopePattern, Text: "some memory"},
			wantErr: true,
		},
		{
			name:    "unknown scope rejected",
			mem:     Memory{Scope: MemoryScope("unknown"), Text: "some memory"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := tempDir(t)
			store, err := OpenMemoryStore(memoryPath(dir))
			if err != nil {
				t.Fatalf("OpenMemoryStore: %v", err)
			}

			err = store.Add(tc.mem)
			if (err != nil) != tc.wantErr {
				t.Errorf("Add() error = %v, wantErr %v", err, tc.wantErr)
			}

			if !tc.wantErr {
				all := store.All()
				if len(all) != 1 {
					t.Errorf("expected 1 memory after Add, got %d", len(all))
				}
				if all[0] != tc.mem {
					t.Errorf("stored memory: got %+v, want %+v", all[0], tc.mem)
				}
			}
		})
	}
}

// TestMemoryStore_ForScanner verifies filtering by scanner ID.
func TestMemoryStore_ForScanner(t *testing.T) {
	dir := tempDir(t)
	store, err := OpenMemoryStore(memoryPath(dir))
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}

	memories := []Memory{
		{Scope: ScopeProject, Text: "global context"},
		{Scope: ScopeScanner, Scanner: "S7", Text: "scanner S7 note"},
		{Scope: ScopeScanner, Scanner: "S12", Text: "scanner S12 note"},
		{Scope: ScopePattern, FileMatch: "**/*.go", Text: "Go files"},
	}
	for _, m := range memories {
		if err := store.Add(m); err != nil {
			t.Fatalf("Add(%+v): %v", m, err)
		}
	}

	tests := []struct {
		scannerID string
		wantTexts []string
	}{
		{
			scannerID: "S7",
			wantTexts: []string{"global context", "scanner S7 note"},
		},
		{
			scannerID: "S12",
			wantTexts: []string{"global context", "scanner S12 note"},
		},
		{
			scannerID: "S99",
			wantTexts: []string{"global context"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.scannerID, func(t *testing.T) {
			got := store.ForScanner(tc.scannerID)
			var texts []string
			for _, m := range got {
				texts = append(texts, m.Text)
			}
			if !reflect.DeepEqual(texts, tc.wantTexts) {
				t.Errorf("ForScanner(%s): got %v, want %v", tc.scannerID, texts, tc.wantTexts)
			}
		})
	}
}

// TestMemoryStore_ForFile verifies glob matching against file paths.
func TestMemoryStore_ForFile(t *testing.T) {
	dir := tempDir(t)
	store, err := OpenMemoryStore(memoryPath(dir))
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}

	memories := []Memory{
		{Scope: ScopeProject, Text: "global context"},
		{Scope: ScopePattern, FileMatch: "**/*.controller.ts", Text: "controller note"},
		{Scope: ScopePattern, FileMatch: "**/*.service.ts", Text: "service note"},
		{Scope: ScopeScanner, Scanner: "S7", Text: "scanner note"},
	}
	for _, m := range memories {
		if err := store.Add(m); err != nil {
			t.Fatalf("Add(%+v): %v", m, err)
		}
	}

	tests := []struct {
		file      string
		wantTexts []string
	}{
		{
			file:      "src/auth/auth.controller.ts",
			wantTexts: []string{"global context", "controller note"},
		},
		{
			file:      "src/users/users.service.ts",
			wantTexts: []string{"global context", "service note"},
		},
		{
			file:      "src/main.ts",
			wantTexts: []string{"global context"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			got := store.ForFile(tc.file)
			var texts []string
			for _, m := range got {
				texts = append(texts, m.Text)
			}
			if !reflect.DeepEqual(texts, tc.wantTexts) {
				t.Errorf("ForFile(%s): got %v, want %v", tc.file, texts, tc.wantTexts)
			}
		})
	}
}

// TestMemoryStore_Remove verifies removal by index.
func TestMemoryStore_Remove(t *testing.T) {
	dir := tempDir(t)
	store, err := OpenMemoryStore(memoryPath(dir))
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}

	for _, m := range []Memory{
		{Scope: ScopeProject, Text: "first"},
		{Scope: ScopeProject, Text: "second"},
		{Scope: ScopeProject, Text: "third"},
	} {
		if err := store.Add(m); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	// Remove middle element (index 1).
	if err := store.Remove(1); err != nil {
		t.Fatalf("Remove(1): %v", err)
	}

	all := store.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 memories after remove, got %d", len(all))
	}
	if all[0].Text != "first" || all[1].Text != "third" {
		t.Errorf("unexpected memories after remove: %+v", all)
	}

	// Out-of-range removal returns an error.
	if err := store.Remove(5); err == nil {
		t.Error("expected error for out-of-range index, got nil")
	}
	if err := store.Remove(-1); err == nil {
		t.Error("expected error for negative index, got nil")
	}
}

// TestMemoryStore_RoundTrip saves a store, reloads it, and verifies equality.
func TestMemoryStore_RoundTrip(t *testing.T) {
	dir := tempDir(t)
	path := memoryPath(dir)

	original := []Memory{
		{Scope: ScopeProject, Text: "project mem 1"},
		{Scope: ScopeProject, Text: "project mem 2"},
		{Scope: ScopeScanner, Scanner: "S7", Text: "scanner S7 mem"},
		{Scope: ScopeScanner, Scanner: "S12", Text: "scanner S12 mem"},
		{Scope: ScopePattern, FileMatch: "**/*.ts", Text: "ts pattern mem"},
		{Scope: ScopePattern, FileMatch: "**/*.go", Text: "go pattern mem"},
	}

	store, err := OpenMemoryStore(path)
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}
	for _, m := range original {
		if err := store.Add(m); err != nil {
			t.Fatalf("Add(%+v): %v", m, err)
		}
	}

	// Reload from disk.
	store2, err := OpenMemoryStore(path)
	if err != nil {
		t.Fatalf("OpenMemoryStore (reload): %v", err)
	}

	reloaded := store2.All()

	// Build a set from original for order-independent comparison (scanner map
	// ordering is non-deterministic across YAML round-trips).
	if len(reloaded) != len(original) {
		t.Fatalf("round-trip count mismatch: got %d, want %d\nreloaded: %+v", len(reloaded), len(original), reloaded)
	}

	origSet := make(map[Memory]bool, len(original))
	for _, m := range original {
		origSet[m] = true
	}
	for _, m := range reloaded {
		if !origSet[m] {
			t.Errorf("unexpected memory after round-trip: %+v", m)
		}
	}
}
