package knowledge

import (
	"fmt"
	"io/fs"
	"os"
	"sort"
)

// SourceType identifies where knowledge comes from.
type SourceType string

const (
	SourceBuiltin SourceType = "builtin"  // go:embed baseline
	SourceLocal   SourceType = "local"    // ~/.sentinella2/kb/
	SourceProject SourceType = "project"  // .sentinella2/kb/
	SourceRemote  SourceType = "remote"   // local clone of git repo
)

// KnowledgeSource describes one source of knowledge.
type KnowledgeSource struct {
	Type     SourceType `yaml:"type"`
	Path     string     `yaml:"path"`     // filesystem path or URL
	Priority int        `yaml:"priority"` // higher overrides lower
	Enabled  bool       `yaml:"enabled"`
}

// MergeStrategy controls how conflicts are resolved.
type MergeStrategy string

const (
	MergeOverlay  MergeStrategy = "overlay"  // later source wins for same ID
	MergeStrict   MergeStrategy = "strict"   // error on ID conflict
	MergeAdditive MergeStrategy = "additive" // keep all, append source suffix
)

// Resolver merges multiple knowledge sources into a single KnowledgeBase.
type Resolver struct {
	sources  []KnowledgeSource
	strategy MergeStrategy
}

// NewResolver creates a Resolver that will merge the given sources using the
// specified strategy. Sources are sorted by priority internally; the original
// slice is not modified.
func NewResolver(sources []KnowledgeSource, strategy MergeStrategy) *Resolver {
	sorted := make([]KnowledgeSource, len(sources))
	copy(sorted, sources)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	return &Resolver{
		sources:  sorted,
		strategy: strategy,
	}
}

// Resolve loads and merges all enabled sources in priority order, returning a
// unified KnowledgeBase. builtinFS and builtinRoot are used for SourceBuiltin
// entries; all other source types load from the filesystem path in the source.
func (r *Resolver) Resolve(builtinFS fs.FS, builtinRoot string) (KnowledgeBase, error) {
	var merged KnowledgeBase
	initialized := false

	for _, src := range r.sources {
		if !src.Enabled {
			continue
		}

		kb, err := r.loadSource(src, builtinFS, builtinRoot)
		if err != nil {
			return KnowledgeBase{}, fmt.Errorf("loading source %s (%s): %w",
				src.Type, src.Path, err)
		}

		if !initialized {
			merged = kb
			initialized = true
			continue
		}

		merged, err = mergeKBs(merged, kb, r.strategy)
		if err != nil {
			return KnowledgeBase{}, fmt.Errorf("merging source %s (%s): %w",
				src.Type, src.Path, err)
		}
	}

	if !initialized {
		return KnowledgeBase{}, fmt.Errorf("no enabled knowledge sources")
	}

	return merged, nil
}

// loadSource loads a single KnowledgeSource into a KnowledgeBase.
func (r *Resolver) loadSource(
	src KnowledgeSource,
	builtinFS fs.FS,
	builtinRoot string,
) (KnowledgeBase, error) {
	switch src.Type {
	case SourceBuiltin:
		return LoadFromFS(builtinFS, builtinRoot)

	case SourceLocal, SourceProject, SourceRemote:
		return loadFromDirSafe(src.Path)

	default:
		return KnowledgeBase{}, fmt.Errorf("unknown source type %q", src.Type)
	}
}

// loadFromDirSafe loads from a directory, returning an empty KB (not an error)
// if the directory does not exist. This allows optional sources like
// ~/.sentinella2/kb/ to be absent without failing the entire resolve.
func loadFromDirSafe(dir string) (KnowledgeBase, error) {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return KnowledgeBase{}, nil
	}
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("stat %q: %w", dir, err)
	}
	if !info.IsDir() {
		return KnowledgeBase{}, fmt.Errorf("path %q is not a directory", dir)
	}
	return LoadFromDir(dir)
}

// mergeKBs merges two knowledge bases according to the strategy. base has
// lower priority, overlay has higher priority.
func mergeKBs(base, overlay KnowledgeBase, strategy MergeStrategy) (KnowledgeBase, error) {
	patterns, err := mergePatterns(base.patterns, overlay.patterns, strategy)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("merging patterns: %w", err)
	}

	cases, err := mergeCases(base.cases, overlay.cases, strategy)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("merging cases: %w", err)
	}

	layers, err := mergeDefenseLayers(base.defenseLayers, overlay.defenseLayers, strategy)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("merging defense layers: %w", err)
	}

	advisories, err := mergeFreeBSDSAs(base.freebsdSAs, overlay.freebsdSAs, strategy)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("merging FreeBSD SAs: %w", err)
	}

	categories, err := mergeOWASPCategories(
		base.owaspCategories, overlay.owaspCategories, strategy,
	)
	if err != nil {
		return KnowledgeBase{}, fmt.Errorf("merging OWASP categories: %w", err)
	}

	pidx, cbp, pbs := buildIndexes(patterns, cases)

	return KnowledgeBase{
		patterns:        patterns,
		cases:           cases,
		defenseLayers:   layers,
		freebsdSAs:      advisories,
		owaspCategories: categories,
		patternIndex:    pidx,
		casesByPattern:  cbp,
		patternsBySev:   pbs,
	}, nil
}

// mergePatterns merges two pattern slices according to the strategy.
func mergePatterns(base, overlay []Pattern, strategy MergeStrategy) ([]Pattern, error) {
	return mergeByID(base, overlay, strategy,
		func(p Pattern) string { return p.ID },
		func(p Pattern, suffix string) Pattern {
			p.ID = p.ID + suffix
			return p
		},
	)
}

// mergeCases merges two case slices according to the strategy.
func mergeCases(base, overlay []Case, strategy MergeStrategy) ([]Case, error) {
	return mergeByID(base, overlay, strategy,
		func(c Case) string { return c.ID },
		func(c Case, suffix string) Case {
			c.ID = c.ID + suffix
			return c
		},
	)
}

// mergeDefenseLayers merges two defense layer slices according to the strategy.
func mergeDefenseLayers(
	base, overlay []DefenseLayer,
	strategy MergeStrategy,
) ([]DefenseLayer, error) {
	return mergeByID(base, overlay, strategy,
		func(l DefenseLayer) string { return l.ID },
		func(l DefenseLayer, suffix string) DefenseLayer {
			l.ID = l.ID + suffix
			return l
		},
	)
}

// mergeFreeBSDSAs merges two FreeBSD SA slices according to the strategy.
func mergeFreeBSDSAs(
	base, overlay []FreeBSDSA,
	strategy MergeStrategy,
) ([]FreeBSDSA, error) {
	return mergeByID(base, overlay, strategy,
		func(sa FreeBSDSA) string { return sa.ID },
		func(sa FreeBSDSA, suffix string) FreeBSDSA {
			sa.ID = sa.ID + suffix
			return sa
		},
	)
}

// mergeOWASPCategories merges two OWASP category slices according to the
// strategy.
func mergeOWASPCategories(
	base, overlay []OWASPCategory,
	strategy MergeStrategy,
) ([]OWASPCategory, error) {
	return mergeByID(base, overlay, strategy,
		func(c OWASPCategory) string { return c.ID },
		func(c OWASPCategory, suffix string) OWASPCategory {
			c.ID = c.ID + suffix
			return c
		},
	)
}

// mergeByID is a generic merge function that works for any type with a string
// ID. getID extracts the ID, withSuffix returns a copy with a modified ID.
func mergeByID[T any](
	base, overlay []T,
	strategy MergeStrategy,
	getID func(T) string,
	withSuffix func(T, string) T,
) ([]T, error) {
	if len(overlay) == 0 {
		return copySlice(base), nil
	}
	if len(base) == 0 {
		return copySlice(overlay), nil
	}

	// Build index of base items by ID.
	baseIndex := make(map[string]int, len(base))
	for i, item := range base {
		baseIndex[getID(item)] = i
	}

	// Start with a copy of base.
	result := copySlice(base)

	for _, item := range overlay {
		id := getID(item)
		baseIdx, conflict := baseIndex[id]

		if !conflict {
			result = append(result, item)
			continue
		}

		switch strategy {
		case MergeOverlay:
			result[baseIdx] = item

		case MergeStrict:
			return nil, fmt.Errorf("conflicting ID %q in strict merge mode", id)

		case MergeAdditive:
			suffixed := withSuffix(item, ":overlay")
			result = append(result, suffixed)

		default:
			return nil, fmt.Errorf("unknown merge strategy %q", strategy)
		}
	}

	return result, nil
}
