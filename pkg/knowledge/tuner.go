package knowledge

// TuneConfig controls how feedback adjusts pattern behavior.
type TuneConfig struct {
	// MinFeedback is the minimum number of feedback entries before adjustments
	// kick in. Patterns with fewer feedback entries are left unchanged.
	MinFeedback int

	// FPThreshold: if false positive rate exceeds this, the rule gets
	// downgraded (confidence lowered, hints added).
	FPThreshold float64

	// HighConfirmThreshold: if confirmation rate exceeds this, the rule gets
	// a confidence boost.
	HighConfirmThreshold float64
}

// DefaultTuneConfig returns sensible defaults for feedback-driven tuning.
func DefaultTuneConfig() TuneConfig {
	return TuneConfig{
		MinFeedback:          5,
		FPThreshold:          0.3,
		HighConfirmThreshold: 0.8,
	}
}

// TuneResult describes what changed for a single pattern after tuning.
type TuneResult struct {
	PatternID  string
	Action     string   // "downgraded", "boosted", "disabled", "unchanged", "new_hint"
	Reason     string
	OldSev     Severity
	NewSev     Severity
	Confidence float64  // 0.0-1.0+ confidence multiplier
	NewHints   []string // new false_positive_hints added
}

// Tuner adjusts patterns based on accumulated feedback. It is stateless;
// configuration is provided at construction time and all state flows through
// the Tune method arguments.
type Tuner struct {
	config TuneConfig
}

// NewTuner creates a Tuner with the given configuration.
func NewTuner(cfg TuneConfig) *Tuner {
	return &Tuner{config: cfg}
}

// Tune takes the current knowledge base and feedback stats, returns a new KB
// with adjusted patterns. The original KB is NOT modified (immutability).
func (t *Tuner) Tune(kb KnowledgeBase, stats []RuleStats) (KnowledgeBase, []TuneResult) {
	statsByPattern := indexStatsByPattern(stats)

	newPatterns := make([]Pattern, len(kb.patterns))
	copy(newPatterns, kb.patterns)

	var results []TuneResult

	for i, p := range newPatterns {
		st, ok := statsByPattern[p.ID]
		if !ok {
			results = append(results, unchangedResult(p))
			continue
		}

		result := t.tunePattern(&newPatterns[i], st)
		results = append(results, result)
	}

	pidx, cbp, pbs := buildIndexes(newPatterns, kb.cases)

	tuned := KnowledgeBase{
		patterns:        newPatterns,
		cases:           copySlice(kb.cases),
		defenseLayers:   copySlice(kb.defenseLayers),
		freebsdSAs:      copySlice(kb.freebsdSAs),
		owaspCategories: copySlice(kb.owaspCategories),
		patternIndex:    pidx,
		casesByPattern:  cbp,
		patternsBySev:   pbs,
	}

	return tuned, results
}

// tunePattern applies feedback-driven adjustments to a single pattern,
// mutating it in place (the caller provides a copy). Returns the TuneResult.
func (t *Tuner) tunePattern(p *Pattern, st RuleStats) TuneResult {
	if st.TotalFeedback < t.config.MinFeedback {
		return unchangedResult(*p)
	}

	fpRate := st.FalsePositiveRate
	confirmRate := confirmationRate(st)

	// Disabled: extreme false positive rate.
	if fpRate > 0.8 {
		return disabledResult(*p, fpRate)
	}

	// Downgraded: high false positive rate warrants severity reduction.
	if fpRate > 0.5 {
		oldSev := p.Severity
		newSev := downgradeSeverity(oldSev)
		hints := fpHints(st)
		p.Severity = newSev
		p.Detection = withAddedHints(p.Detection, hints)

		return TuneResult{
			PatternID:  p.ID,
			Action:     "downgraded",
			Reason:     "false positive rate exceeds 0.5, severity reduced",
			OldSev:     oldSev,
			NewSev:     newSev,
			Confidence: 0.5,
			NewHints:   hints,
		}
	}

	// New hints: moderate false positive rate.
	if fpRate > t.config.FPThreshold {
		hints := fpHints(st)
		p.Detection = withAddedHints(p.Detection, hints)

		return TuneResult{
			PatternID:  p.ID,
			Action:     "new_hint",
			Reason:     "false positive rate exceeds threshold, added hints",
			OldSev:     p.Severity,
			NewSev:     p.Severity,
			Confidence: 0.7,
			NewHints:   hints,
		}
	}

	// Boosted: high confirmation rate.
	if confirmRate > t.config.HighConfirmThreshold {
		return TuneResult{
			PatternID:  p.ID,
			Action:     "boosted",
			Reason:     "high confirmation rate indicates reliable detection",
			OldSev:     p.Severity,
			NewSev:     p.Severity,
			Confidence: 1.2,
		}
	}

	return unchangedResult(*p)
}

// indexStatsByPattern builds a lookup map from pattern ID to RuleStats.
func indexStatsByPattern(stats []RuleStats) map[string]RuleStats {
	m := make(map[string]RuleStats, len(stats))
	for _, s := range stats {
		m[s.PatternRef] = s
	}
	return m
}

// confirmationRate computes the ratio of confirmed findings to total feedback.
func confirmationRate(st RuleStats) float64 {
	if st.TotalFeedback == 0 {
		return 0
	}
	return float64(st.Confirmed) / float64(st.TotalFeedback)
}

// downgradeSeverity reduces severity by one level. LOW stays LOW.
func downgradeSeverity(sev Severity) Severity {
	switch sev {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// withAddedHints returns a new Detection with additional false positive hints
// appended. The original Detection is not modified.
func withAddedHints(d Detection, hints []string) Detection {
	if len(hints) == 0 {
		return d
	}

	existing := copySlice(d.FalsePositiveHints)
	seen := make(map[string]bool, len(existing))
	for _, h := range existing {
		seen[h] = true
	}

	for _, h := range hints {
		if !seen[h] {
			existing = append(existing, h)
			seen[h] = true
		}
	}

	// Copy rules map to avoid shared references.
	rules := copyRulesMap(d.Rules)

	return Detection{
		Abstract:           d.Abstract,
		Tier:               d.Tier,
		Rules:              rules,
		FalsePositiveHints: existing,
	}
}

// copyRulesMap returns a shallow copy of a rules map.
func copyRulesMap(src map[string]RuleSet) map[string]RuleSet {
	if src == nil {
		return nil
	}
	dst := make(map[string]RuleSet, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// fpHints generates false positive hint strings from feedback statistics.
func fpHints(st RuleStats) []string {
	var hints []string
	if st.FalsePositives > 0 {
		hints = append(hints, "auto-tuned: high false positive rate detected in feedback")
	}
	if st.TotalFeedback > 0 && st.FalsePositiveRate > 0.5 {
		hints = append(hints, "auto-tuned: consider manual review of detection rules")
	}
	return hints
}

// unchangedResult builds a TuneResult for a pattern that was not modified.
func unchangedResult(p Pattern) TuneResult {
	return TuneResult{
		PatternID:  p.ID,
		Action:     "unchanged",
		Reason:     "insufficient feedback or within acceptable thresholds",
		OldSev:     p.Severity,
		NewSev:     p.Severity,
		Confidence: 1.0,
	}
}

// disabledResult builds a TuneResult for a pattern that should be skipped.
func disabledResult(p Pattern, _ float64) TuneResult {
	return TuneResult{
		PatternID:  p.ID,
		Action:     "disabled",
		Reason:     "false positive rate exceeds 0.8, pattern should be skipped",
		OldSev:     p.Severity,
		NewSev:     p.Severity,
		Confidence: 0.0,
	}
}
