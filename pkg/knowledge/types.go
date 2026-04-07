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

// Pattern represents a vulnerability detection pattern with language-specific
// rules and fix templates.
type Pattern struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Severity    Severity  `yaml:"severity"`
	OWASP       []string  `yaml:"owasp"`
	FreeBSDSA   []string  `yaml:"freebsd_sa"`
	Detection   Detection `yaml:"detection"`
	Fix         Fix       `yaml:"fix"`
	Cases       []string  `yaml:"cases"`
}

// Detection holds the detection strategy for a pattern, including per-language
// regex rules and false-positive hints.
type Detection struct {
	Abstract           string              `yaml:"abstract"`
	Tier               int                 `yaml:"tier"`
	Rules              map[string]RuleSet  `yaml:"rules"`
	FalsePositiveHints []string            `yaml:"false_positive_hints"`
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
