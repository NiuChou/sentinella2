package knowledge

// KnowledgeBase holds the complete loaded knowledge base. Fields are unexported
// to enforce immutability; all accessors return copies.
type KnowledgeBase struct {
	patterns        []Pattern
	cases           []Case
	defenseLayers   []DefenseLayer
	freebsdSAs      []FreeBSDSA
	owaspCategories []OWASPCategory

	// Pre-built indexes for fast lookup.
	patternIndex    map[string]int // pattern ID -> index in patterns
	casesByPattern  map[string][]int // pattern ref -> indexes in cases
	patternsBySev   map[Severity][]int // severity -> indexes in patterns
}

// Patterns returns a copy of all loaded vulnerability patterns.
func (kb KnowledgeBase) Patterns() []Pattern {
	return copySlice(kb.patterns)
}

// Cases returns a copy of all loaded vulnerability cases.
func (kb KnowledgeBase) Cases() []Case {
	return copySlice(kb.cases)
}

// DefenseLayers returns a copy of all loaded defense-in-depth layers.
func (kb KnowledgeBase) DefenseLayers() []DefenseLayer {
	return copySlice(kb.defenseLayers)
}

// FreeBSDSAs returns a copy of all loaded FreeBSD Security Advisory mappings.
func (kb KnowledgeBase) FreeBSDSAs() []FreeBSDSA {
	return copySlice(kb.freebsdSAs)
}

// OWASPCategories returns a copy of all loaded OWASP Top 10 category mappings.
func (kb KnowledgeBase) OWASPCategories() []OWASPCategory {
	return copySlice(kb.owaspCategories)
}

// PatternByID returns the pattern with the given ID and true, or a zero value
// and false if no such pattern exists.
func (kb KnowledgeBase) PatternByID(id string) (Pattern, bool) {
	idx, ok := kb.patternIndex[id]
	if !ok {
		return Pattern{}, false
	}
	return kb.patterns[idx], true
}

// CasesByPatternRef returns all cases that reference the given pattern ID.
func (kb KnowledgeBase) CasesByPatternRef(ref string) []Case {
	indexes, ok := kb.casesByPattern[ref]
	if !ok {
		return nil
	}
	out := make([]Case, len(indexes))
	for i, idx := range indexes {
		out[i] = kb.cases[idx]
	}
	return out
}

// PatternsBySeverity returns all patterns that match the given severity level.
func (kb KnowledgeBase) PatternsBySeverity(sev Severity) []Pattern {
	indexes, ok := kb.patternsBySev[sev]
	if !ok {
		return nil
	}
	out := make([]Pattern, len(indexes))
	for i, idx := range indexes {
		out[i] = kb.patterns[idx]
	}
	return out
}

// PatternsForTier returns all patterns whose detection tier is less than or
// equal to the given tier. Tier 1 returns only tier-1 patterns; tier 2
// returns tier 1 and 2; tier 3 returns all.
func (kb KnowledgeBase) PatternsForTier(tier int) []Pattern {
	var out []Pattern
	for _, p := range kb.patterns {
		if p.Detection.Tier <= tier {
			out = append(out, p)
		}
	}
	return out
}

// PatternCount returns the total number of loaded patterns.
func (kb KnowledgeBase) PatternCount() int {
	return len(kb.patterns)
}

// CaseCount returns the total number of loaded cases.
func (kb KnowledgeBase) CaseCount() int {
	return len(kb.cases)
}

// buildIndexes creates the lookup maps from the loaded data. Called once
// during construction; the resulting KnowledgeBase is immutable after this.
func buildIndexes(patterns []Pattern, cases []Case) (
	patternIndex map[string]int,
	casesByPattern map[string][]int,
	patternsBySev map[Severity][]int,
) {
	patternIndex = make(map[string]int, len(patterns))
	for i, p := range patterns {
		patternIndex[p.ID] = i
	}

	casesByPattern = make(map[string][]int)
	for i, c := range cases {
		casesByPattern[c.PatternRef] = append(casesByPattern[c.PatternRef], i)
	}

	patternsBySev = make(map[Severity][]int)
	for i, p := range patterns {
		patternsBySev[p.Severity] = append(patternsBySev[p.Severity], i)
	}

	return patternIndex, casesByPattern, patternsBySev
}

// NewKnowledgeBaseForTest constructs a KnowledgeBase from the given slices.
// Intended for use in tests outside this package. Production code should use
// LoadFromFS or the resolver.
func NewKnowledgeBaseForTest(
	patterns []Pattern,
	cases []Case,
	layers []DefenseLayer,
	sas []FreeBSDSA,
	owasp []OWASPCategory,
) KnowledgeBase {
	pidx, cbp, pbs := buildIndexes(patterns, cases)
	return KnowledgeBase{
		patterns:        copySlice(patterns),
		cases:           copySlice(cases),
		defenseLayers:   copySlice(layers),
		freebsdSAs:      copySlice(sas),
		owaspCategories: copySlice(owasp),
		patternIndex:    pidx,
		casesByPattern:  cbp,
		patternsBySev:   pbs,
	}
}

// copySlice returns a shallow copy of a slice so callers cannot mutate the
// internal state of KnowledgeBase.
func copySlice[T any](src []T) []T {
	if src == nil {
		return nil
	}
	dst := make([]T, len(src))
	copy(dst, src)
	return dst
}
