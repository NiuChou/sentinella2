package knowledge

import "time"

// FeedConfig describes a vulnerability feed source. All fields are public value
// types to keep FeedConfig immutable when passed by value.
type FeedConfig struct {
	ID       string `yaml:"id"`
	URL      string `yaml:"url"`
	Type     string `yaml:"type"`     // "nvd", "freebsd-sa", "github-advisory"
	Schedule string `yaml:"schedule"` // cron expression or "daily"/"weekly"
	Enabled  bool   `yaml:"enabled"`
}

// FeedEntry is a normalized vulnerability entry from any feed source. Each feed
// parser converts its native format into this common representation so the
// updater can treat all sources uniformly.
type FeedEntry struct {
	SourceID    string    // CVE-2026-XXXX or GHSA-XXXX or SA-26:XX
	Source      string    // "nvd", "freebsd-sa", "github-advisory"
	Title       string
	Description string
	Severity    Severity
	CWEs        []string  // CWE IDs, e.g. "CWE-79"
	AffectedPkg []string  // affected packages/components
	Published   time.Time
	References  []string  // URLs
	RawJSON     []byte    // original response for debugging
}

// FeedResult holds the output of a feed sync operation. Error is a non-fatal
// error message; a FeedResult with a non-empty Error may still contain partial
// entries that were successfully parsed before the error occurred.
type FeedResult struct {
	Feed      FeedConfig
	Entries   []FeedEntry
	NewCount  int       // entries not previously seen
	FetchedAt time.Time
	Error     string    // non-fatal error message, empty on full success
}

// IncrementalEntry represents a single proposed change to the knowledge base
// derived from a feed entry. It carries enough context for human review before
// the change is applied.
type IncrementalEntry struct {
	Type       string    // "case", "pattern_update", "advisory"
	SourceID   string    // CVE/GHSA/SA identifier
	PatternRef string    // matched pattern ID from cweToPattern mapping
	Entry      FeedEntry
	Confidence float64   // mapping confidence 0.0-1.0
	Status     string    // "pending_review", "auto_approved", "rejected"
}

// feedState tracks per-feed sync metadata for persistence.
type feedState struct {
	FeedID    string    `yaml:"feed_id"`
	LastSync  time.Time `yaml:"last_sync"`
	LastCount int       `yaml:"last_count"`
}

// stateFile is the top-level structure of the state.yaml persistence file.
type stateFile struct {
	SchemaVersion string      `yaml:"schema_version"`
	Feeds         []feedState `yaml:"feeds"`
}

// DefaultFeeds returns the pre-configured vulnerability feed sources. These
// cover the three major advisory databases: NVD for CVEs, FreeBSD-SA for
// kernel/system advisories, and GitHub Advisory for open-source packages.
func DefaultFeeds() []FeedConfig {
	return []FeedConfig{
		{
			ID:       "nvd",
			URL:      "https://services.nvd.nist.gov/rest/json/cves/2.0",
			Type:     "nvd",
			Schedule: "daily",
			Enabled:  true,
		},
		{
			ID:       "freebsd-sa",
			URL:      "https://www.freebsd.org/security/advisories.rdf",
			Type:     "freebsd-sa",
			Schedule: "daily",
			Enabled:  true,
		},
		{
			ID:       "github-advisory",
			URL:      "https://api.github.com/advisories",
			Type:     "github-advisory",
			Schedule: "daily",
			Enabled:  true,
		},
	}
}

// cwePatternMap returns the mapping from CWE identifiers to sentinella2 pattern
// reference prefixes. The map is rebuilt on each call to avoid shared mutable
// state.
func cwePatternMap() map[string]string {
	return map[string]string{
		"CWE-20":  "input-boundary/*",
		"CWE-22":  "input-boundary/*",
		"CWE-78":  "injection/command-injection",
		"CWE-79":  "injection/content-injection",
		"CWE-89":  "injection/*",
		"CWE-200": "info-leakage/*",
		"CWE-287": "auth-flow/*",
		"CWE-306": "auth-flow/*",
		"CWE-352": "auth-flow/csrf-missing",
		"CWE-639": "auth-flow/idor",
		"CWE-798": "info-leakage/config-leak",
	}
}
