package knowledge

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// registrySchemaVersion is the current schema version for registry YAML files.
const registrySchemaVersion = "1.0"

// registryFileName is the name of the registry persistence file within the
// registry directory.
const registryFileName = "registry.yaml"

// RegistryEntry represents a registered external knowledge source.
type RegistryEntry struct {
	Name        string    `yaml:"name"`
	URL         string    `yaml:"url"`
	Description string    `yaml:"description"`
	LocalPath   string    `yaml:"local_path"`
	AddedAt     time.Time `yaml:"added_at"`
	UpdatedAt   time.Time `yaml:"updated_at"`
	Enabled     bool      `yaml:"enabled"`
}

// registryFile is the on-disk YAML representation of the registry.
type registryFile struct {
	SchemaVersion string          `yaml:"schema_version"`
	Kind          string          `yaml:"kind"`
	Entries       []RegistryEntry `yaml:"entries"`
}

// Registry manages external knowledge sources (community repos).
// It persists entries as a YAML file under the configured directory.
type Registry struct {
	dir     string // e.g. ~/.sentinella2/registries/
	entries []RegistryEntry
}

// OpenRegistry loads an existing registry from dir, or initializes an empty
// one if no registry file exists yet. The directory is created if absent.
func OpenRegistry(dir string) (*Registry, error) {
	if dir == "" {
		return nil, fmt.Errorf("open registry: directory path must not be empty")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("open registry: create directory: %w", err)
	}

	path := filepath.Join(dir, registryFileName)
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("open registry: read file: %w", err)
	}

	var entries []RegistryEntry
	if err == nil && len(data) > 0 {
		var file registryFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("open registry: parse yaml: %w", err)
		}
		if file.SchemaVersion != registrySchemaVersion {
			return nil, fmt.Errorf("open registry: unsupported schema version: %q (expected %q)",
				file.SchemaVersion, registrySchemaVersion)
		}
		entries = file.Entries
	}

	return &Registry{
		dir:     dir,
		entries: entries,
	}, nil
}

// Add registers a new external knowledge source. It validates the name and URL
// format but does NOT clone the repository; the caller handles git operations.
func (r *Registry) Add(name, rawURL, description string) (RegistryEntry, error) {
	if err := validateName(name); err != nil {
		return RegistryEntry{}, fmt.Errorf("add registry entry: %w", err)
	}

	if err := validateURL(rawURL); err != nil {
		return RegistryEntry{}, fmt.Errorf("add registry entry: %w", err)
	}

	if r.findIndex(name) >= 0 {
		return RegistryEntry{}, fmt.Errorf("add registry entry: name %q already registered", name)
	}

	now := time.Now().UTC()
	entry := RegistryEntry{
		Name:        name,
		URL:         rawURL,
		Description: description,
		LocalPath:   filepath.Join(r.dir, name),
		AddedAt:     now,
		UpdatedAt:   now,
		Enabled:     true,
	}

	// Build new entries slice (immutable append).
	updated := make([]RegistryEntry, len(r.entries), len(r.entries)+1)
	copy(updated, r.entries)
	updated = append(updated, entry)
	r.entries = updated

	if err := r.save(); err != nil {
		return RegistryEntry{}, fmt.Errorf("add registry entry: %w", err)
	}

	return entry, nil
}

// Remove unregisters a knowledge source by name. It does NOT delete the local
// clone directory; the caller handles cleanup.
func (r *Registry) Remove(name string) error {
	idx := r.findIndex(name)
	if idx < 0 {
		return fmt.Errorf("remove registry entry: name %q not found", name)
	}

	updated := make([]RegistryEntry, 0, len(r.entries)-1)
	updated = append(updated, r.entries[:idx]...)
	updated = append(updated, r.entries[idx+1:]...)
	r.entries = updated

	if err := r.save(); err != nil {
		return fmt.Errorf("remove registry entry: %w", err)
	}

	return nil
}

// List returns a copy of all registered entries.
func (r *Registry) List() []RegistryEntry {
	out := make([]RegistryEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Sources returns KnowledgeSource entries for enabled registries, suitable for
// passing to a knowledge base Resolver.
func (r *Registry) Sources() []KnowledgeSource {
	var sources []KnowledgeSource
	for i, e := range r.entries {
		if e.Enabled {
			sources = append(sources, KnowledgeSource{
				Type:     SourceRemote,
				Path:     e.LocalPath,
				Priority: 100 + i, // remote sources get higher priority
				Enabled:  true,
			})
		}
	}
	return sources
}

// save persists the current registry state to disk as YAML.
func (r *Registry) save() error {
	file := registryFile{
		SchemaVersion: registrySchemaVersion,
		Kind:          "registry",
		Entries:       r.entries,
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}

	path := filepath.Join(r.dir, registryFileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write registry file: %w", err)
	}

	return nil
}

// findIndex returns the index of the entry with the given name, or -1.
func (r *Registry) findIndex(name string) int {
	for i, e := range r.entries {
		if e.Name == name {
			return i
		}
	}
	return -1
}

// --- validation helpers ---

// validateName checks that a registry name is a non-empty, URL-safe identifier.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("name must not exceed 64 characters")
	}
	for _, ch := range name {
		if !isNameChar(ch) {
			return fmt.Errorf("name contains invalid character %q: only a-z, 0-9, dash, underscore allowed", ch)
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") {
		return fmt.Errorf("name must start with a letter or digit")
	}
	return nil
}

// isNameChar reports whether ch is valid in a registry name.
func isNameChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
}

// validateURL checks that the raw URL is parseable and uses https or ssh scheme.
func validateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("url must not be empty")
	}

	// Accept git@host:path SSH URLs.
	if strings.HasPrefix(rawURL, "git@") {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}

	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("url scheme must be https or http, got %q", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("url must include a host")
	}

	return nil
}
