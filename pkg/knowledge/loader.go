package knowledge

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFromFS loads the knowledge base from any fs.FS implementation. The root
// parameter is the directory within fsys that contains the patterns/, cases/,
// defense-layers/, and mappings/ subdirectories. Use this with embed.FS or
// os.DirFS for testing with custom knowledge directories.
func LoadFromFS(fsys fs.FS, root string) (KnowledgeBase, error) {
	patterns, err := loadPatterns(fsys, root)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("loading patterns: %w", err)
	}

	cases, err := loadCases(fsys, root)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("loading cases: %w", err)
	}

	layers, err := loadDefenseLayers(fsys, root)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("loading defense layers: %w", err)
	}

	advisories, err := loadFreeBSDSAs(fsys, root)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("loading FreeBSD SA mappings: %w", err)
	}

	categories, err := loadOWASPCategories(fsys, root)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("loading OWASP mappings: %w", err)
	}

	patternIdx, casesByPattern, patternsBySev := buildIndexes(patterns, cases)

	return KnowledgeBase{
		patterns:        patterns,
		cases:           cases,
		defenseLayers:   layers,
		freebsdSAs:      advisories,
		owaspCategories: categories,
		patternIndex:    patternIdx,
		casesByPattern:  casesByPattern,
		patternsBySev:   patternsBySev,
	}, nil
}

// LoadFromDir loads the knowledge base from a directory on the local filesystem.
// This is the primary entry point for library consumers who are not embedding
// the knowledge base into their binary.
func LoadFromDir(dir string) (KnowledgeBase, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("knowledge directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return KnowledgeBase{}, fmt.Errorf("knowledge path %q is not a directory", dir)
	}
	return LoadFromFS(os.DirFS(dir), ".")
}

// loadPatterns reads all YAML files from {root}/patterns/ and collects every
// pattern entry into a flat slice.
func loadPatterns(fsys fs.FS, root string) ([]Pattern, error) {
	dir := filepath.Join(root, "patterns")
	files, err := listYAMLFiles(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("listing pattern files in %s: %w", dir, err)
	}

	var all []Pattern
	for _, path := range files {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var pf patternFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		for _, p := range pf.Patterns {
			if p.ID == "" {
				return nil, fmt.Errorf("pattern in %s missing required field 'id'", path)
			}
			if !p.Severity.IsValid() {
				return nil, fmt.Errorf("pattern %q in %s has invalid severity %q", p.ID, path, p.Severity)
			}
			all = append(all, p)
		}
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no patterns found in %s", dir)
	}
	return all, nil
}

// loadCases reads all YAML files from {root}/cases/ and collects every case
// entry into a flat slice.
func loadCases(fsys fs.FS, root string) ([]Case, error) {
	dir := filepath.Join(root, "cases")
	files, err := listYAMLFiles(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("listing case files in %s: %w", dir, err)
	}

	var all []Case
	for _, path := range files {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var cf caseFile
		if err := yaml.Unmarshal(data, &cf); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		for _, c := range cf.Cases {
			if c.ID == "" {
				return nil, fmt.Errorf("case in %s missing required field 'id'", path)
			}
			if !c.Severity.IsValid() {
				return nil, fmt.Errorf("case %q in %s has invalid severity %q", c.ID, path, c.Severity)
			}
			all = append(all, c)
		}
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no cases found in %s", dir)
	}
	return all, nil
}

// loadDefenseLayers reads the defense layer definitions from
// {root}/defense-layers/layers.yaml.
func loadDefenseLayers(fsys fs.FS, root string) ([]DefenseLayer, error) {
	path := filepath.Join(root, "defense-layers", "layers.yaml")
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var dlf defenseLayerFile
	if err := yaml.Unmarshal(data, &dlf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if len(dlf.Layers) == 0 {
		return nil, fmt.Errorf("no defense layers found in %s", path)
	}

	for _, l := range dlf.Layers {
		if l.ID == "" {
			return nil, fmt.Errorf("defense layer in %s missing required field 'id'", path)
		}
	}
	return dlf.Layers, nil
}

// loadFreeBSDSAs reads FreeBSD SA mappings from {root}/mappings/freebsd-sa.yaml.
func loadFreeBSDSAs(fsys fs.FS, root string) ([]FreeBSDSA, error) {
	path := filepath.Join(root, "mappings", "freebsd-sa.yaml")
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var f freebsdSAFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	for _, sa := range f.Advisories {
		if sa.ID == "" {
			return nil, fmt.Errorf("FreeBSD SA in %s missing required field 'id'", path)
		}
	}
	return f.Advisories, nil
}

// loadOWASPCategories reads OWASP Top 10 mappings from
// {root}/mappings/owasp-top10.yaml.
func loadOWASPCategories(fsys fs.FS, root string) ([]OWASPCategory, error) {
	path := filepath.Join(root, "mappings", "owasp-top10.yaml")
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var f owaspFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	for _, c := range f.Categories {
		if c.ID == "" {
			return nil, fmt.Errorf("OWASP category in %s missing required field 'id'", path)
		}
	}
	return f.Categories, nil
}

// listYAMLFiles returns sorted paths of all .yaml files in the given directory
// within fsys. It does not recurse into subdirectories.
func listYAMLFiles(fsys fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}
