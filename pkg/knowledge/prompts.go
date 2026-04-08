package knowledge

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PromptTemplate holds a loaded audit prompt template from the knowledge base.
type PromptTemplate struct {
	SchemaVersion string   `yaml:"schema_version"`
	Kind          string   `yaml:"kind"`
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	PatternRefs   []string `yaml:"pattern_refs"`
	Prompt        string   `yaml:"prompt"`
}

// LoadPrompts reads all prompt YAML files from {root}/prompts/ within fsys.
// Returns a map keyed by prompt ID (e.g., "system", "input-boundary").
func LoadPrompts(fsys fs.FS, root string) (map[string]PromptTemplate, error) {
	dir := filepath.Join(root, "prompts")
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading prompts directory %s: %w", dir, err)
	}

	prompts := make(map[string]PromptTemplate)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var pt PromptTemplate
		if err := yaml.Unmarshal(data, &pt); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		if pt.ID == "" {
			continue
		}
		prompts[pt.ID] = pt
	}

	return prompts, nil
}
