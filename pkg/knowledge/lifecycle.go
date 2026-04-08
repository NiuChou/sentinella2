package knowledge

import "fmt"

// LifecycleConfig holds thresholds for automatic pattern status transitions.
type LifecycleConfig struct {
	PromoteToTesting PromotionRule
	PromoteToStable  PromotionRule
	AutoDeprecate    DeprecateRule
}

// PromotionRule describes the conditions required to promote a pattern.
type PromotionRule struct {
	MinScans         int
	MinTruePositives int
	MinConfidence    float64
}

// DeprecateRule describes the conditions that trigger automatic deprecation.
type DeprecateRule struct {
	MaxFPRate  float64
	MinSamples int
}

// Transition describes a recommended status change for a single pattern.
type Transition struct {
	PatternID string
	OldStatus string
	NewStatus string
	Reason    string
}

// LifecycleEngine evaluates pattern status transitions based on feedback data.
// It is stateless after construction; all state flows through method arguments.
type LifecycleEngine struct {
	config LifecycleConfig
}

// NewLifecycleEngine creates a LifecycleEngine with the given configuration.
func NewLifecycleEngine(cfg LifecycleConfig) *LifecycleEngine {
	return &LifecycleEngine{config: cfg}
}

// Evaluate checks all patterns and returns recommended transitions.
// It does NOT mutate the patterns — the caller decides whether to apply them.
// Patterns with no matching stats entry are skipped (no transition recommended).
// Deprecated patterns are never resurrected.
func (e *LifecycleEngine) Evaluate(patterns []Pattern, stats []RuleStats) []Transition {
	statsIdx := indexStatsByPattern(stats)

	var transitions []Transition
	for _, p := range patterns {
		st, ok := statsIdx[p.ID]
		if !ok {
			continue
		}
		t := e.evaluate(p, st)
		if t != nil {
			transitions = append(transitions, *t)
		}
	}
	return transitions
}

// Apply returns a new pattern slice with all transitions applied.
// The original patterns slice is NOT modified (immutability).
func (e *LifecycleEngine) Apply(patterns []Pattern, transitions []Transition) []Pattern {
	if len(transitions) == 0 {
		result := make([]Pattern, len(patterns))
		copy(result, patterns)
		return result
	}

	byID := make(map[string]Transition, len(transitions))
	for _, t := range transitions {
		byID[t.PatternID] = t
	}

	result := make([]Pattern, len(patterns))
	for i, p := range patterns {
		if t, ok := byID[p.ID]; ok {
			updated := p
			updated.Status = t.NewStatus
			result[i] = updated
		} else {
			result[i] = p
		}
	}
	return result
}

// evaluate returns a Transition for the pattern if one is warranted, or nil otherwise.
func (e *LifecycleEngine) evaluate(p Pattern, st RuleStats) *Transition {
	// Deprecated patterns stay deprecated — no resurrection.
	if p.Status == StatusDeprecated {
		return nil
	}

	// Auto-deprecate takes priority over promotion.
	if e.shouldDeprecate(st) {
		return &Transition{
			PatternID: p.ID,
			OldStatus: p.Status,
			NewStatus: StatusDeprecated,
			Reason: fmt.Sprintf(
				"false positive rate %.2f exceeds threshold %.2f with %d samples",
				st.FalsePositiveRate,
				e.config.AutoDeprecate.MaxFPRate,
				st.TotalFeedback,
			),
		}
	}

	switch p.Status {
	case StatusExperimental:
		if e.shouldPromoteToTesting(st) {
			return &Transition{
				PatternID: p.ID,
				OldStatus: StatusExperimental,
				NewStatus: StatusTesting,
				Reason: fmt.Sprintf(
					"met promotion thresholds: %d scans, %d true positives",
					st.TotalFeedback,
					st.Confirmed,
				),
			}
		}
	case StatusTesting:
		if e.shouldPromoteToStable(st) {
			return &Transition{
				PatternID: p.ID,
				OldStatus: StatusTesting,
				NewStatus: StatusStable,
				Reason: fmt.Sprintf(
					"met promotion thresholds: %d scans, precision %.2f, %d true positives",
					st.TotalFeedback,
					st.Precision,
					st.Confirmed,
				),
			}
		}
	}

	return nil
}

// shouldDeprecate reports whether the stats indicate this pattern should be deprecated.
func (e *LifecycleEngine) shouldDeprecate(st RuleStats) bool {
	d := e.config.AutoDeprecate
	return st.TotalFeedback >= d.MinSamples && st.FalsePositiveRate > d.MaxFPRate
}

// shouldPromoteToTesting reports whether an experimental pattern meets the
// thresholds for promotion to testing.
func (e *LifecycleEngine) shouldPromoteToTesting(st RuleStats) bool {
	r := e.config.PromoteToTesting
	return st.TotalFeedback >= r.MinScans && st.Confirmed >= r.MinTruePositives
}

// shouldPromoteToStable reports whether a testing pattern meets the thresholds
// for promotion to stable.
func (e *LifecycleEngine) shouldPromoteToStable(st RuleStats) bool {
	r := e.config.PromoteToStable
	return st.TotalFeedback >= r.MinScans &&
		st.Precision >= r.MinConfidence &&
		st.Confirmed >= r.MinTruePositives
}
