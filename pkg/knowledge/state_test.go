package knowledge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// sampleState returns a populated FindingState for reuse across tests.
func sampleState(status FindingStatus) FindingState {
	return FindingState{
		Status:     status,
		PatternRef: "injection/sql",
		File:       "src/db/query.go",
		MsgPattern: "SQL query built from user input",
		FirstSeen:  time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		LabeledAt:  time.Date(2026, 4, 2, 9, 0, 0, 0, time.UTC),
		LabeledBy:  "analyst@example.com",
		Reason:     "confirmed via manual review",
		Tags:       []string{"reviewed", "critical-path"},
	}
}

func TestStateStore_OpenCreate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")

	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}

	// File must exist on disk after open.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state.json not created: %v", err)
	}

	// File must be valid JSON with correct version.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var sf findingStateFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		t.Fatalf("parse state.json: %v", err)
	}
	if sf.Version != stateFileVersion {
		t.Errorf("version: got %d, want %d", sf.Version, stateFileVersion)
	}
}

func TestStateStore_OpenCreateMissingDir(t *testing.T) {
	t.Parallel()

	// Path inside a non-existent subdirectory — should be created automatically.
	path := filepath.Join(t.TempDir(), "nested", "dir", "state.json")

	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore with missing parent dir: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestStateStore_OpenEmptyPath(t *testing.T) {
	t.Parallel()

	_, err := OpenStateStore("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestStateStore_LoadExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Seed a state.json with one finding.
	seed := findingStateFile{
		Version:  stateFileVersion,
		LastScan: time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC),
		Findings: map[string]FindingState{
			"injection/sql-aabbccdd": sampleState(StatusConfirmed),
		},
	}
	raw, _ := json.MarshalIndent(seed, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}

	state, ok := store.Get("injection/sql-aabbccdd")
	if !ok {
		t.Fatal("expected finding to be loaded from disk")
	}
	if state.Status != StatusConfirmed {
		t.Errorf("status: got %q, want %q", state.Status, StatusConfirmed)
	}
	if state.PatternRef != "injection/sql" {
		t.Errorf("pattern_ref: got %q, want %q", state.PatternRef, "injection/sql")
	}
}

func TestStateStore_UpdateAndGet(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const id = "auth/idor-11223344"
	state := sampleState(StatusOpen)

	if err := store.Update(id, state); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, ok := store.Get(id)
	if !ok {
		t.Fatal("Get: finding not found after Update")
	}
	if got.Status != StatusOpen {
		t.Errorf("Status: got %q, want %q", got.Status, StatusOpen)
	}

	// Update again to a different status.
	updated := sampleState(StatusConfirmed)
	if err := store.Update(id, updated); err != nil {
		t.Fatalf("second Update: %v", err)
	}

	got2, _ := store.Get(id)
	if got2.Status != StatusConfirmed {
		t.Errorf("Status after second update: got %q, want %q", got2.Status, StatusConfirmed)
	}
}

func TestStateStore_UpdatePersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const id = "crypto/weak-hash-deadbeef"
	if err := store.Update(id, sampleState(StatusFalsePositive)); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Re-open from disk and verify the finding survived.
	store2, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := store2.Get(id)
	if !ok {
		t.Fatal("finding not found after reload")
	}
	if got.Status != StatusFalsePositive {
		t.Errorf("Status after reload: got %q, want %q", got.Status, StatusFalsePositive)
	}
}

func TestStateStore_GetMissing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	_, ok := store.Get("nonexistent-id")
	if ok {
		t.Error("expected Get to return false for missing ID")
	}
}

func TestStateStore_FindingsByStatus(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	updates := []struct {
		id     string
		status FindingStatus
	}{
		{"id-open-1", StatusOpen},
		{"id-open-2", StatusOpen},
		{"id-confirmed-1", StatusConfirmed},
		{"id-fp-1", StatusFalsePositive},
		{"id-accepted-1", StatusAccepted},
		{"id-fixed-1", StatusFixed},
	}

	for _, u := range updates {
		if err := store.Update(u.id, sampleState(u.status)); err != nil {
			t.Fatalf("Update %s: %v", u.id, err)
		}
	}

	openFindings := store.FindingsByStatus(StatusOpen)
	if len(openFindings) != 2 {
		t.Errorf("FindingsByStatus(open): got %d, want 2", len(openFindings))
	}

	confirmedFindings := store.FindingsByStatus(StatusConfirmed)
	if len(confirmedFindings) != 1 {
		t.Errorf("FindingsByStatus(confirmed): got %d, want 1", len(confirmedFindings))
	}

	fixedFindings := store.FindingsByStatus(StatusFixed)
	if len(fixedFindings) != 1 {
		t.Errorf("FindingsByStatus(fixed): got %d, want 1", len(fixedFindings))
	}

	// Empty status should return an empty map, not nil.
	noneFindings := store.FindingsByStatus("nonexistent_status")
	if noneFindings == nil {
		t.Error("FindingsByStatus with unknown status: got nil, want empty map")
	}
	if len(noneFindings) != 0 {
		t.Errorf("FindingsByStatus with unknown status: got %d entries, want 0", len(noneFindings))
	}
}

func TestStateStore_FindingsByStatusReturnsCopy(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const id = "injection/sql-copy-test"
	if err := store.Update(id, sampleState(StatusOpen)); err != nil {
		t.Fatalf("Update: %v", err)
	}

	result := store.FindingsByStatus(StatusOpen)
	// Mutate the returned map — should not affect the store.
	delete(result, id)

	result2 := store.FindingsByStatus(StatusOpen)
	if _, ok := result2[id]; !ok {
		t.Error("mutating FindingsByStatus result affected the store")
	}
}

func TestStateStore_RecordScan(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	scanTime := time.Date(2026, 4, 7, 8, 0, 0, 0, time.UTC)
	store.RecordScan(scanTime)

	// Reload from disk and verify last_scan was persisted.
	store2, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = store2 // last_scan is internal; verify indirectly via JSON.

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var sf findingStateFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !sf.LastScan.Equal(scanTime) {
		t.Errorf("last_scan: got %v, want %v", sf.LastScan, scanTime)
	}
}

func TestStateStore_Save(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := store.Update("id-1", sampleState(StatusOpen)); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("state.json missing after Save: %v", err)
	}
}

func TestStateStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // writers + readers

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			id := filepath.Join("injection/sql", string(rune('a'+n%26)))
			state := sampleState(StatusOpen)
			_ = store.Update(id, state)
		}(i)

		go func(n int) {
			defer wg.Done()
			id := filepath.Join("injection/sql", string(rune('a'+n%26)))
			_, _ = store.Get(id)
		}(i)
	}

	wg.Wait()

	// At least some entries should have been written (no panic or data corruption).
	openFindings := store.FindingsByStatus(StatusOpen)
	if len(openFindings) == 0 {
		t.Error("expected at least one open finding after concurrent writes")
	}
}
