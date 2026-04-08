// Package knowledge provides types and loaders for the sentinella2 security
// knowledge base, including the Context Memory system for project-scoped
// declarations that affect scanner behavior.
package knowledge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// MemoryScope classifies where a memory applies.
type MemoryScope string

const (
	ScopeProject MemoryScope = "project"
	ScopeScanner MemoryScope = "scanner"
	ScopePattern MemoryScope = "pattern"
)

// Memory represents a user-declared project context that affects scanner behavior.
type Memory struct {
	Scope     MemoryScope `yaml:"scope"`
	Scanner   string      `yaml:"scanner,omitempty"`
	FileMatch string      `yaml:"match,omitempty"`
	Text      string      `yaml:"memory"`
}

// MemoryEffectType classifies how a memory affects scanning.
type MemoryEffectType string

const (
	EffectProtectionDeclared MemoryEffectType = "protection_declared"
	EffectNotApplicable      MemoryEffectType = "not_applicable"
	EffectSafePattern        MemoryEffectType = "safe_pattern"
)

// MemoryEffect is the structured interpretation of a Memory.
type MemoryEffect struct {
	Scope              MemoryScope
	Effect             MemoryEffectType
	AffectedScanners   []string // empty = all scanners
	FilePatterns       []string // glob patterns for affected files
	ConfidenceOverride float64  // 0.0 = full trust in declaration
}

// memorySchemaVersion is the current schema version for memories.yaml files.
const memorySchemaVersion = "1.0"

// memoryFile is the top-level YAML structure for .sentinella2/memories.yaml.
// The three-level structure mirrors the spec:
//
//	schema_version: "1.0"
//	kind: memories
//	project:
//	  - "text"
//	scanners:
//	  S7:
//	    - "text"
//	patterns:
//	  - match: "**/*.controller.ts"
//	    memory: "text"
type memoryFile struct {
	SchemaVersion string              `yaml:"schema_version"`
	Kind          string              `yaml:"kind"`
	Project       []string            `yaml:"project,omitempty"`
	Scanners      map[string][]string `yaml:"scanners,omitempty"`
	Patterns      []patternMemory     `yaml:"patterns,omitempty"`
}

// patternMemory is the on-disk representation of a pattern-scoped memory.
type patternMemory struct {
	Match  string `yaml:"match"`
	Memory string `yaml:"memory"`
}

// MemoryStore provides access to the user-declared memory store. The store is
// backed by a single YAML file (default: .sentinella2/memories.yaml relative
// to the project root, or the path provided to OpenMemoryStore).
type MemoryStore struct {
	path     string
	memories []Memory
}

// OpenMemoryStore loads the memory store from path. If the file does not exist,
// an empty store is returned and the file is created on the first Save or Add.
func OpenMemoryStore(path string) (*MemoryStore, error) {
	ms := &MemoryStore{path: path}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ms, nil
		}
		return nil, fmt.Errorf("open memory store %s: %w", path, err)
	}

	if len(data) == 0 {
		return ms, nil
	}

	var mf memoryFile
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("parse memory store %s: %w", path, err)
	}

	memories := parseMemoryFile(mf)
	return &MemoryStore{path: path, memories: memories}, nil
}

// All returns a copy of all memories in the store.
func (ms *MemoryStore) All() []Memory {
	if len(ms.memories) == 0 {
		return nil
	}
	cp := make([]Memory, len(ms.memories))
	copy(cp, ms.memories)
	return cp
}

// ForScanner returns memories applicable to the given scanner ID. This
// includes all project-scoped memories and scanner-scoped memories whose
// Scanner field matches scannerID.
func (ms *MemoryStore) ForScanner(scannerID string) []Memory {
	var result []Memory
	for _, m := range ms.memories {
		switch m.Scope {
		case ScopeProject:
			result = append(result, m)
		case ScopeScanner:
			if m.Scanner == scannerID {
				result = append(result, m)
			}
		}
	}
	return result
}

// ForFile returns memories applicable to the given relative file path. This
// includes all project-scoped memories and pattern-scoped memories whose
// FileMatch glob matches relPath.
func (ms *MemoryStore) ForFile(relPath string) []Memory {
	var result []Memory
	for _, m := range ms.memories {
		switch m.Scope {
		case ScopeProject:
			result = append(result, m)
		case ScopePattern:
			matched, err := matchGlob(m.FileMatch, relPath)
			if err == nil && matched {
				result = append(result, m)
			}
		}
	}
	return result
}

// Add appends a new memory to the store and persists it to disk.
func (ms *MemoryStore) Add(mem Memory) error {
	if err := validateMemory(mem); err != nil {
		return fmt.Errorf("invalid memory: %w", err)
	}
	updated := make([]Memory, len(ms.memories)+1)
	copy(updated, ms.memories)
	updated[len(ms.memories)] = mem
	ms.memories = updated
	return ms.Save()
}

// Remove removes the memory at the given zero-based index and persists the
// updated store to disk.
func (ms *MemoryStore) Remove(index int) error {
	if index < 0 || index >= len(ms.memories) {
		return fmt.Errorf("index %d out of range [0, %d)", index, len(ms.memories))
	}
	updated := make([]Memory, 0, len(ms.memories)-1)
	updated = append(updated, ms.memories[:index]...)
	updated = append(updated, ms.memories[index+1:]...)
	ms.memories = updated
	return ms.Save()
}

// Save persists the current state of the store to disk. It creates parent
// directories if they do not exist.
func (ms *MemoryStore) Save() error {
	dir := filepath.Dir(ms.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create memory store directory %s: %w", dir, err)
	}

	mf := buildMemoryFile(ms.memories)
	data, err := yaml.Marshal(mf)
	if err != nil {
		return fmt.Errorf("marshal memory store: %w", err)
	}

	if err := os.WriteFile(ms.path, data, 0o644); err != nil {
		return fmt.Errorf("write memory store %s: %w", ms.path, err)
	}
	return nil
}

// --- internal helpers ---

// parseMemoryFile converts the three-level YAML structure into a flat []Memory.
func parseMemoryFile(mf memoryFile) []Memory {
	var memories []Memory

	for _, text := range mf.Project {
		memories = append(memories, Memory{
			Scope: ScopeProject,
			Text:  text,
		})
	}

	for scannerID, texts := range mf.Scanners {
		for _, text := range texts {
			memories = append(memories, Memory{
				Scope:   ScopeScanner,
				Scanner: scannerID,
				Text:    text,
			})
		}
	}

	for _, pm := range mf.Patterns {
		memories = append(memories, Memory{
			Scope:     ScopePattern,
			FileMatch: pm.Match,
			Text:      pm.Memory,
		})
	}

	return memories
}

// buildMemoryFile converts a flat []Memory back to the three-level YAML structure.
func buildMemoryFile(memories []Memory) memoryFile {
	mf := memoryFile{
		SchemaVersion: memorySchemaVersion,
		Kind:          "memories",
	}

	for _, m := range memories {
		switch m.Scope {
		case ScopeProject:
			mf.Project = append(mf.Project, m.Text)
		case ScopeScanner:
			if mf.Scanners == nil {
				mf.Scanners = make(map[string][]string)
			}
			mf.Scanners[m.Scanner] = append(mf.Scanners[m.Scanner], m.Text)
		case ScopePattern:
			mf.Patterns = append(mf.Patterns, patternMemory{
				Match:  m.FileMatch,
				Memory: m.Text,
			})
		}
	}

	return mf
}

// validateMemory checks that a Memory has the required fields for its scope.
func validateMemory(m Memory) error {
	if strings.TrimSpace(m.Text) == "" {
		return fmt.Errorf("memory text must not be empty")
	}
	switch m.Scope {
	case ScopeProject:
		// no additional fields required
	case ScopeScanner:
		if strings.TrimSpace(m.Scanner) == "" {
			return fmt.Errorf("scanner-scoped memory requires a non-empty scanner ID")
		}
	case ScopePattern:
		if strings.TrimSpace(m.FileMatch) == "" {
			return fmt.Errorf("pattern-scoped memory requires a non-empty match glob")
		}
	default:
		return fmt.Errorf("unknown scope %q; must be one of: project, scanner, pattern", m.Scope)
	}
	return nil
}

// matchGlob wraps filepath.Match with support for ** double-star segments.
// A ** segment matches any number of path components (including zero).
func matchGlob(pattern, name string) (bool, error) {
	// Fast path: no double-star, delegate to filepath.Match.
	if !strings.Contains(pattern, "**") {
		return filepath.Match(pattern, name)
	}

	// Replace ** with a multi-segment placeholder, then try matching each
	// possible expansion. We split on ** and require each non-** part to
	// appear in order within the path.
	parts := strings.Split(pattern, "**")
	return matchDoubleStar(parts, name)
}

// matchDoubleStar recursively matches name against the parts split on "**".
// Each part is an ordinary filepath.Match pattern (no **).
func matchDoubleStar(parts []string, name string) (bool, error) {
	if len(parts) == 0 {
		return name == "", nil
	}

	first := parts[0]
	rest := parts[1:]

	if len(rest) == 0 {
		// Last part: the remainder of name must match first (possibly empty).
		if first == "" {
			return true, nil
		}
		// first may start with "/" — strip leading slash for matching.
		trimmed := strings.TrimPrefix(first, "/")
		if trimmed == "" {
			return true, nil
		}
		// Match the suffix of name against first.
		return filepath.Match(trimmed, filepath.Base(name))
	}

	// Try all possible split points in name for the ** expansion.
	// The segment before ** (first) must match the start of name.
	trimFirst := strings.TrimSuffix(strings.TrimPrefix(first, "/"), "/")
	if trimFirst != "" {
		matched, err := filepath.Match(trimFirst, firstSegment(name))
		if err != nil {
			return false, err
		}
		if !matched {
			// first part must match the very beginning
			_ = matched
		}
	}

	// Try all possible suffix lengths for **.
	pathParts := strings.Split(name, "/")
	for i := 0; i <= len(pathParts); i++ {
		suffix := strings.Join(pathParts[i:], "/")
		ok, err := matchDoubleStar(rest, suffix)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// firstSegment returns the first path component of s.
func firstSegment(s string) string {
	idx := strings.IndexByte(s, '/')
	if idx < 0 {
		return s
	}
	return s[:idx]
}

// DefaultMemoryPath returns the default memory store path for a given project
// root directory.
func DefaultMemoryPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".sentinella2", "memories.yaml")
}

// MemoryIndexLabel returns a human-readable label for displaying a memory at
// index i (1-based for UI display).
func MemoryIndexLabel(i int) string {
	return "[" + strconv.Itoa(i+1) + "]"
}
