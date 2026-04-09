package knowledge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FindingStatus represents the lifecycle state of a tracked finding.
type FindingStatus string

const (
	StatusOpen          FindingStatus = "open"
	StatusConfirmed     FindingStatus = "confirmed"
	StatusFalsePositive FindingStatus = "false_positive"
	StatusAccepted      FindingStatus = "accepted"
	StatusFixed         FindingStatus = "fixed"
)

// stateFileVersion is the current JSON schema version for state.json.
const stateFileVersion = 1

// FindingState records the persisted lifecycle state for a single finding,
// keyed by its stable ID in the StateStore.
type FindingState struct {
	Status     FindingStatus `json:"status"`
	PatternRef string        `json:"pattern_ref"`
	File       string        `json:"file"`
	MsgPattern string        `json:"message_pattern"`
	FirstSeen  time.Time     `json:"first_seen"`
	LabeledAt  time.Time     `json:"labeled_at,omitempty"`
	LabeledBy  string        `json:"labeled_by,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
}

// findingStateFile is the on-disk representation of the finding state store.
type findingStateFile struct {
	Version  int                     `json:"version"`
	LastScan time.Time               `json:"last_scan"`
	Findings map[string]FindingState `json:"findings"` // key = stable ID
}

// StateStore is a thread-safe, JSON-backed store that tracks the lifecycle
// state of findings across scans. It is machine-generated state, not
// human-authored config, hence JSON rather than YAML.
type StateStore struct {
	mu   sync.RWMutex
	path string
	data findingStateFile
}

// OpenStateStore opens an existing state.json at path, or creates a new one
// if the file does not exist. The parent directory is created as needed.
func OpenStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, fmt.Errorf("open state store: path must not be empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("open state store: create directory: %w", err)
	}

	s := &StateStore{path: path}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// New store — initialise with empty data.
		s.data = findingStateFile{
			Version:  stateFileVersion,
			Findings: make(map[string]FindingState),
		}
		// Persist immediately so the file exists after open.
		if err := s.save(); err != nil {
			return nil, fmt.Errorf("open state store: initial save: %w", err)
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open state store: read file: %w", err)
	}

	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("open state store: parse json: %w", err)
	}
	if s.data.Findings == nil {
		s.data.Findings = make(map[string]FindingState)
	}

	return s, nil
}

// Get returns the FindingState for stableID. The second return value is false
// if no entry exists for that ID.
func (s *StateStore) Get(stableID string) (FindingState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fs, ok := s.data.Findings[stableID]
	return fs, ok
}

// Update sets (or replaces) the FindingState for stableID and persists the
// entire store to disk.
func (s *StateStore) Update(stableID string, state FindingState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := copyFindings(s.data.Findings)
	updated[stableID] = state

	next := findingStateFile{
		Version:  s.data.Version,
		LastScan: s.data.LastScan,
		Findings: updated,
	}
	if err := marshalAndWrite(s.path, next); err != nil {
		return fmt.Errorf("update state: %w", err)
	}
	s.data = next
	return nil
}

// RecordScan updates the last_scan timestamp and persists the store.
func (s *StateStore) RecordScan(scanTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := findingStateFile{
		Version:  s.data.Version,
		LastScan: scanTime,
		Findings: s.data.Findings,
	}
	// Best-effort: log nothing on failure; caller can check Save() separately.
	_ = marshalAndWrite(s.path, next)
	s.data = next
}

// FindingsByStatus returns a copy of all findings with the given status.
func (s *StateStore) FindingsByStatus(status FindingStatus) map[string]FindingState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]FindingState)
	for id, fs := range s.data.Findings {
		if fs.Status == status {
			out[id] = fs
		}
	}
	return out
}

// Save writes the current in-memory state to disk.
func (s *StateStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.save(); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}

// --- internal helpers ---

// save writes the current data to disk. Caller must hold at least a read lock.
func (s *StateStore) save() error {
	return marshalAndWrite(s.path, s.data)
}

// marshalAndWrite atomically writes data to path via a temp file rename.
func marshalAndWrite(path string, data findingStateFile) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	// Write to a sibling temp file then rename for atomicity.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// copyFindings returns a shallow copy of the findings map.
func copyFindings(src map[string]FindingState) map[string]FindingState {
	dst := make(map[string]FindingState, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
