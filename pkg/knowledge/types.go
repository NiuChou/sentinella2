// Package knowledge provides types and loaders for the sentinella2 security
// knowledge base. All exported types are value types; accessor methods on
// KnowledgeBase return copies to preserve immutability after construction.
package knowledge

// Severity classifies the impact level of a vulnerability pattern or case.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// ValidSeverities returns the ordered set of valid severity values.
func ValidSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

// IsValid reports whether s is a recognised severity level.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	}
	return false
}

// Status constants define the maturity lifecycle for a pattern rule.
// Inspired by Sigma's status field.
const (
	StatusExperimental = "experimental"
	StatusTesting      = "testing"
	StatusStable       = "stable"
	StatusDeprecated   = "deprecated"
)

// Pattern represents a vulnerability detection pattern with language-specific
// rules and fix templates.
type Pattern struct {
	ID               string   `yaml:"id"`
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description"`
	Severity         Severity `yaml:"severity"`
	OWASP            []string `yaml:"owasp"`
	FreeBSDSA        []string `yaml:"freebsd_sa"`
	Detection        Detection `yaml:"detection"`
	Fix              Fix      `yaml:"fix"`
	Cases            []string `yaml:"cases"`
	Status           string   `yaml:"status,omitempty"`            // experimental, testing, stable, deprecated
	ConfidenceWeight float64  `yaml:"confidence_weight,omitempty"` // multiplier, default 1.0
}

// EffectiveConfidenceWeight returns the confidence weight for a pattern based on its status.
// If ConfidenceWeight is explicitly set, use that. Otherwise derive from status.
func (p Pattern) EffectiveConfidenceWeight() float64 {
	if p.ConfidenceWeight > 0 {
		return p.ConfidenceWeight
	}
	switch p.Status {
	case StatusExperimental:
		return 0.5
	case StatusTesting:
		return 0.75
	case StatusStable, "":
		return 1.0 // default = stable
	case StatusDeprecated:
		return 0.25
	default:
		return 1.0
	}
}

// IsVisibleByDefault returns whether this pattern's findings show in default output.
func (p Pattern) IsVisibleByDefault() bool {
	switch p.Status {
	case StatusExperimental, StatusDeprecated:
		return false
	default:
		return true
	}
}

// CanBlockCI returns whether findings from this pattern can block CI.
func (p Pattern) CanBlockCI() bool {
	return p.Status == StatusStable || p.Status == ""
}

// Detection holds the detection strategy for a pattern, including per-language
// regex rules, false-positive hints, and optional cross-file analysis rules.
type Detection struct {
	Abstract           string              `yaml:"abstract"`
	Tier               int                 `yaml:"tier"`
	Rules              map[string]RuleSet  `yaml:"rules"`
	FalsePositiveHints []string            `yaml:"false_positive_hints"`
	CrossFile          *CrossFileRule      `yaml:"cross_file,omitempty"`
}

// CrossFileRule defines a cross-file analysis strategy that collects matches
// across the codebase and applies relational assertions. Used by CrossFileScanner
// (Tier 2) to detect systemic issues spanning multiple files or platforms.
type CrossFileRule struct {
	// Collect is the regex pattern to gather matches across files.
	Collect string `yaml:"collect"`
	// CollectFrom is the list of file globs to search in.
	CollectFrom []string `yaml:"collect_from"`
	// Assert is the condition to evaluate on grouped matches.
	Assert string `yaml:"assert"`
	// AssertType classifies the kind of cross-file check:
	//   "duplication"   — flag when multiple groups have similar implementations
	//   "consistency"   — flag when extracted values differ across groups
	//   "completeness"  — flag when a required chain of patterns is incomplete
	AssertType string `yaml:"assert_type"`
	// GroupBy controls how matches are grouped. "top_directory" groups by
	// the first path component; "none" treats all matches as one group.
	GroupBy string `yaml:"group_by"`
	// ValueExtract is an optional regex for the "consistency" assert type.
	// The first capture group is used as the extracted value. If empty,
	// a default regex extracting values after : or = is used.
	ValueExtract string `yaml:"value_extract,omitempty"`
}

// RuleSet contains the regex patterns for detecting a vulnerability in a
// specific language. NegativePattern matches code that is already mitigated.
type RuleSet struct {
	Pattern         string `yaml:"pattern"`
	NegativePattern string `yaml:"negative_pattern"`
	Context         string `yaml:"context"`
}

// Fix holds the remediation guidance for a pattern, including per-language
// code templates.
type Fix struct {
	Abstract  string            `yaml:"abstract"`
	Templates map[string]string `yaml:"templates"`
}

// Case represents a real-world vulnerability instance from an audit.
type Case struct {
	ID           string   `yaml:"id"`
	Title        string   `yaml:"title"`
	Severity     Severity `yaml:"severity"`
	PatternRef   string   `yaml:"pattern_ref"`
	FreeBSDSARef string   `yaml:"freebsd_sa_ref"`
	Location     string   `yaml:"location"`
	Description  string   `yaml:"description"`
	FixSummary   string   `yaml:"fix_summary"`
	Lesson       string   `yaml:"lesson"`
}

// DefenseLayer represents one layer of the defense-in-depth security model.
type DefenseLayer struct {
	ID            string       `yaml:"id"`
	Name          string       `yaml:"name"`
	Order         int          `yaml:"order"`
	FreeBSDAnalog string       `yaml:"freebsd_analog"`
	Description   string       `yaml:"description"`
	Checks        []LayerCheck `yaml:"checks"`
}

// LayerCheck is an individual security verification within a defense layer.
type LayerCheck struct {
	ID           string         `yaml:"id"`
	Name         string         `yaml:"name"`
	Description  string         `yaml:"description"`
	PatternRefs  []string       `yaml:"pattern_refs"`
	Tier         int            `yaml:"tier"`
	Verification string         `yaml:"verification"`
	Detection    CheckDetection `yaml:"detection"`
}

// CheckDetection holds the file globs and regex patterns used to verify
// whether a defense-layer check passes or fails.
type CheckDetection struct {
	Files           []string `yaml:"files"`
	Pattern         string   `yaml:"pattern"`
	NegativePattern string   `yaml:"negative_pattern"`
}

// FreeBSDSA maps a FreeBSD Security Advisory to a sentinella2 pattern,
// demonstrating that kernel-level and application-level vulnerabilities
// share common root causes.
type FreeBSDSA struct {
	ID           string `yaml:"id"`
	CVE          string `yaml:"cve"`
	Title        string `yaml:"title"`
	Component    string `yaml:"component"`
	RootCause    string `yaml:"root_cause"`
	PatternRef   string `yaml:"pattern_ref"`
	DefenseLayer string `yaml:"defense_layer"`
	Lesson       string `yaml:"lesson"`
}

// OWASPCategory maps an OWASP Top 10 category to sentinella2 patterns.
type OWASPCategory struct {
	ID             string   `yaml:"id"`
	Name           string   `yaml:"name"`
	Description    string   `yaml:"description"`
	PatternRefs    []string `yaml:"pattern_refs"`
	Coverage       string   `yaml:"coverage"`
	FreeBSDAnalogs []string `yaml:"freebsd_analogs"`
}

// --- Internal YAML wrapper types (not exported) ---

// patternFile is the top-level structure of a patterns/*.yaml file.
type patternFile struct {
	SchemaVersion string    `yaml:"schema_version"`
	Kind          string    `yaml:"kind"`
	Category      string    `yaml:"category"`
	Patterns      []Pattern `yaml:"patterns"`
}

// caseFile is the top-level structure of a cases/*.yaml file.
type caseFile struct {
	SchemaVersion  string   `yaml:"schema_version"`
	Kind           string   `yaml:"kind"`
	SeverityFilter string   `yaml:"severity_filter"`
	Cases          []Case   `yaml:"cases"`
}

// defenseLayerFile is the top-level structure of defense-layers/layers.yaml.
type defenseLayerFile struct {
	SchemaVersion string         `yaml:"schema_version"`
	Kind          string         `yaml:"kind"`
	Layers        []DefenseLayer `yaml:"layers"`
}

// freebsdSAFile is the top-level structure of mappings/freebsd-sa.yaml.
type freebsdSAFile struct {
	SchemaVersion string      `yaml:"schema_version"`
	Kind          string      `yaml:"kind"`
	Advisories    []FreeBSDSA `yaml:"advisories"`
}

// owaspFile is the top-level structure of mappings/owasp-top10.yaml.
type owaspFile struct {
	SchemaVersion string          `yaml:"schema_version"`
	Kind          string          `yaml:"kind"`
	OWASPVersion  string          `yaml:"owasp_version"`
	Categories    []OWASPCategory `yaml:"categories"`
}
