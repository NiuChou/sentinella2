package knowledge

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// httpClient is the interface used for HTTP requests. It matches *http.Client
// and allows injection of test doubles.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Updater fetches vulnerability feeds, maps entries to existing patterns, and
// writes incremental YAML files. It never mutates the current KnowledgeBase;
// all changes are staged as files in stateDir for explicit review and apply.
type Updater struct {
	feeds    []FeedConfig
	current  KnowledgeBase
	stateDir string
	client   httpClient
}

// NewUpdater constructs an Updater. The feeds slice is copied to prevent
// external mutation. stateDir is created if it does not exist.
func NewUpdater(feeds []FeedConfig, current KnowledgeBase, stateDir string) *Updater {
	return &Updater{
		feeds:    copySlice(feeds),
		current:  current,
		stateDir: stateDir,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// WithHTTPClient returns a new Updater that uses the given HTTP client. This
// supports testing without real network calls.
func (u *Updater) WithHTTPClient(c httpClient) *Updater {
	return &Updater{
		feeds:    u.feeds,
		current:  u.current,
		stateDir: u.stateDir,
		client:   c,
	}
}

// Sync fetches all enabled feeds and returns results. It does NOT modify the
// current knowledge base. Each feed is fetched sequentially to respect rate
// limits. Non-fatal per-feed errors are captured in FeedResult.Error.
func (u *Updater) Sync(ctx context.Context) ([]FeedResult, error) {
	var results []FeedResult

	for _, feed := range u.feeds {
		if !feed.Enabled {
			continue
		}

		if err := ctx.Err(); err != nil {
			return results, fmt.Errorf("sync cancelled: %w", err)
		}

		entries, fetchErr := u.fetchFeed(ctx, feed)
		now := time.Now().UTC()

		result := FeedResult{
			Feed:      feed,
			Entries:   entries,
			FetchedAt: now,
		}

		if fetchErr != nil {
			result.Error = fetchErr.Error()
		}

		result.NewCount = u.countNew(feed.ID, entries)
		results = append(results, result)

		if fetchErr == nil {
			_ = u.writeSyncState(feed.ID, now, len(entries))
		}
	}

	return results, nil
}

// MapToPatterns maps feed entries to existing pattern refs based on CWE and
// keyword matching. Each entry may produce zero or one IncrementalEntry.
// Entries without a CWE match are mapped with lower confidence via keyword
// fallback.
func (u *Updater) MapToPatterns(entries []FeedEntry) []IncrementalEntry {
	cweMap := cwePatternMap()
	var result []IncrementalEntry

	for _, entry := range entries {
		mapped := u.mapSingleEntry(entry, cweMap)
		if mapped.PatternRef != "" {
			result = append(result, mapped)
		}
	}

	return result
}

// Diff returns a human-readable summary of what would change if the given
// incremental entries were applied. This is intended for CLI preview output.
func (u *Updater) Diff(entries []IncrementalEntry) string {
	if len(entries) == 0 {
		return "No changes to apply."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Proposed changes: %d entries\n", len(entries))
	b.WriteString(strings.Repeat("-", 60))
	b.WriteString("\n")

	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Type]++
	}

	for typ, count := range counts {
		fmt.Fprintf(&b, "  %-20s %d\n", typ+":", count)
	}
	b.WriteString("\n")

	for _, e := range entries {
		fmt.Fprintf(&b, "[%s] %s -> %s (confidence: %.0f%%, status: %s)\n",
			e.Type, e.SourceID, e.PatternRef,
			e.Confidence*100, e.Status)
	}

	return b.String()
}

// Apply writes incremental entries as individual YAML files to stateDir. Each
// entry is written to a file named by its source ID. Existing files for the
// same source ID are overwritten. The stateDir is created if it does not exist.
func (u *Updater) Apply(entries []IncrementalEntry) error {
	dir := filepath.Join(u.stateDir, "incremental")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating incremental directory: %w", err)
	}

	for _, entry := range entries {
		if err := u.writeIncrementalFile(dir, entry); err != nil {
			return fmt.Errorf("writing entry %s: %w", entry.SourceID, err)
		}
	}

	return nil
}

// LastSyncTime reads the last successful sync timestamp for a feed from the
// persisted state file. Returns zero time if the feed has never been synced.
func (u *Updater) LastSyncTime(feedID string) (time.Time, error) {
	state, err := u.readState()
	if err != nil {
		return time.Time{}, err
	}

	for _, fs := range state.Feeds {
		if fs.FeedID == feedID {
			return fs.LastSync, nil
		}
	}

	return time.Time{}, nil
}

// --- Feed fetchers ---

func (u *Updater) fetchFeed(ctx context.Context, feed FeedConfig) ([]FeedEntry, error) {
	switch feed.Type {
	case "nvd":
		return u.fetchNVD(ctx, feed)
	case "freebsd-sa":
		return u.fetchFreeBSDSA(ctx, feed)
	case "github-advisory":
		return u.fetchGitHubAdvisory(ctx, feed)
	default:
		return nil, fmt.Errorf("unknown feed type %q", feed.Type)
	}
}

// --- NVD fetcher ---

// nvdResponse is the top-level NVD 2.0 API response.
type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Weaknesses   []nvdWeakness    `json:"weaknesses"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseSeverity string  `json:"baseSeverity"`
	BaseScore    float64 `json:"baseScore"`
}

type nvdReference struct {
	URL string `json:"url"`
}

func (u *Updater) fetchNVD(ctx context.Context, feed FeedConfig) ([]FeedEntry, error) {
	lastSync, _ := u.LastSyncTime(feed.ID)
	if lastSync.IsZero() {
		lastSync = time.Now().UTC().AddDate(0, 0, -7)
	}

	now := time.Now().UTC()
	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s",
		feed.URL,
		lastSync.Format("2006-01-02T15:04:05.000"),
		now.Format("2006-01-02T15:04:05.000"))

	body, err := u.httpGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching NVD: %w", err)
	}

	var resp nvdResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing NVD response: %w", err)
	}

	entries := make([]FeedEntry, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		entry := nvdCVEToEntry(v.CVE, body)
		entries = append(entries, entry)
	}

	return entries, nil
}

func nvdCVEToEntry(cve nvdCVE, rawJSON []byte) FeedEntry {
	entry := FeedEntry{
		SourceID: cve.ID,
		Source:   "nvd",
		RawJSON:  rawJSON,
	}

	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			entry.Title = truncate(d.Value, 120)
			entry.Description = d.Value
			break
		}
	}

	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
				entry.CWEs = append(entry.CWEs, d.Value)
			}
		}
	}

	entry.Severity = nvdSeverityToSeverity(cve.Metrics)

	for _, ref := range cve.References {
		entry.References = append(entry.References, ref.URL)
	}

	if t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
		entry.Published = t
	}

	return entry
}

func nvdSeverityToSeverity(metrics nvdMetrics) Severity {
	if len(metrics.CvssMetricV31) == 0 {
		return SeverityMedium
	}
	switch strings.ToUpper(metrics.CvssMetricV31[0].CVSSData.BaseSeverity) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// --- FreeBSD SA fetcher ---

// rssChannel and rssItem model a minimal RSS 2.0 / RDF feed.
type rssFeed struct {
	XMLName xml.Name   `xml:"RDF"`
	Items   []rssItem  `xml:"item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	Date        string `xml:"date"`
}

func (u *Updater) fetchFreeBSDSA(ctx context.Context, feed FeedConfig) ([]FeedEntry, error) {
	body, err := u.httpGet(ctx, feed.URL)
	if err != nil {
		return nil, fmt.Errorf("fetching FreeBSD SA feed: %w", err)
	}

	var rss rssFeed
	if err := xml.Unmarshal(body, &rss); err != nil {
		return nil, fmt.Errorf("parsing FreeBSD SA RSS: %w", err)
	}

	entries := make([]FeedEntry, 0, len(rss.Items))
	for _, item := range rss.Items {
		entry := rssItemToEntry(item)
		entries = append(entries, entry)
	}

	return entries, nil
}

func rssItemToEntry(item rssItem) FeedEntry {
	entry := FeedEntry{
		SourceID:    extractSAID(item.Title),
		Source:      "freebsd-sa",
		Title:       item.Title,
		Description: item.Description,
		Severity:    SeverityHigh, // FreeBSD SAs are typically HIGH+
		References:  []string{item.Link},
	}

	if t, err := time.Parse(time.RFC3339, item.Date); err == nil {
		entry.Published = t
	}

	return entry
}

// extractSAID pulls "FreeBSD-SA-26:01" from a title like
// "FreeBSD-SA-26:01.something -- description".
func extractSAID(title string) string {
	parts := strings.SplitN(title, ".", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return title
}

// --- GitHub Advisory fetcher ---

type ghAdvisory struct {
	GHSAID      string   `json:"ghsa_id"`
	CVEID       string   `json:"cve_id"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CWEs        []ghCWE  `json:"cwes"`
	PublishedAt string   `json:"published_at"`
	HTMLURL     string   `json:"html_url"`
	Identifiers []ghID   `json:"identifiers"`
	Vulnerabilities []ghVuln `json:"vulnerabilities"`
}

type ghCWE struct {
	CWEID string `json:"cwe_id"`
}

type ghID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ghVuln struct {
	Package ghPkg `json:"package"`
}

type ghPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

func (u *Updater) fetchGitHubAdvisory(ctx context.Context, feed FeedConfig) ([]FeedEntry, error) {
	url := feed.URL + "?type=reviewed&per_page=100"

	body, err := u.httpGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetching GitHub advisories: %w", err)
	}

	var advisories []ghAdvisory
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("parsing GitHub advisory response: %w", err)
	}

	entries := make([]FeedEntry, 0, len(advisories))
	for _, adv := range advisories {
		entry := ghAdvisoryToEntry(adv, body)
		entries = append(entries, entry)
	}

	return entries, nil
}

func ghAdvisoryToEntry(adv ghAdvisory, rawJSON []byte) FeedEntry {
	sourceID := adv.GHSAID
	if adv.CVEID != "" {
		sourceID = adv.CVEID
	}

	entry := FeedEntry{
		SourceID:    sourceID,
		Source:      "github-advisory",
		Title:       adv.Summary,
		Description: adv.Description,
		Severity:    ghSeverityToSeverity(adv.Severity),
		References:  []string{adv.HTMLURL},
		RawJSON:     rawJSON,
	}

	for _, cwe := range adv.CWEs {
		entry.CWEs = append(entry.CWEs, cwe.CWEID)
	}

	for _, vuln := range adv.Vulnerabilities {
		pkg := vuln.Package.Ecosystem + "/" + vuln.Package.Name
		entry.AffectedPkg = append(entry.AffectedPkg, pkg)
	}

	if t, err := time.Parse(time.RFC3339, adv.PublishedAt); err == nil {
		entry.Published = t
	}

	return entry
}

func ghSeverityToSeverity(sev string) Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// --- Pattern mapping ---

func (u *Updater) mapSingleEntry(entry FeedEntry, cweMap map[string]string) IncrementalEntry {
	inc := IncrementalEntry{
		SourceID: entry.SourceID,
		Entry:    entry,
		Status:   "pending_review",
	}

	// Determine type from source.
	switch entry.Source {
	case "freebsd-sa":
		inc.Type = "advisory"
	default:
		inc.Type = "case"
	}

	// Try CWE-based mapping first (highest confidence).
	bestConfidence := 0.0
	for _, cwe := range entry.CWEs {
		if patternRef, ok := cweMap[cwe]; ok {
			resolved := u.resolveWildcard(patternRef)
			if resolved != "" && 0.8 > bestConfidence {
				inc.PatternRef = resolved
				bestConfidence = 0.8
			}
		}
	}

	// Keyword fallback for entries without CWE matches.
	if inc.PatternRef == "" {
		ref, conf := u.keywordMatch(entry)
		if ref != "" {
			inc.PatternRef = ref
			bestConfidence = conf
		}
	}

	inc.Confidence = bestConfidence

	// Auto-approve high-confidence, high-severity entries.
	if inc.Confidence >= 0.8 && (entry.Severity == SeverityCritical || entry.Severity == SeverityHigh) {
		inc.Status = "auto_approved"
	}

	return inc
}

// resolveWildcard resolves a pattern ref like "injection/*" to the first
// matching pattern in the current knowledge base. If the ref is not a wildcard,
// it verifies the pattern exists. Returns empty string if no match.
func (u *Updater) resolveWildcard(ref string) string {
	if !strings.HasSuffix(ref, "/*") {
		if _, ok := u.current.PatternByID(ref); ok {
			return ref
		}
		return ""
	}

	prefix := strings.TrimSuffix(ref, "*")
	for _, p := range u.current.Patterns() {
		if strings.HasPrefix(p.ID, prefix) {
			return p.ID
		}
	}

	// Return the wildcard prefix without trailing slash as a placeholder
	// when no existing pattern matches.
	return strings.TrimSuffix(prefix, "/")
}

// keywordMatch attempts to match a feed entry to a pattern by scanning the
// entry title and description for pattern-related keywords.
func (u *Updater) keywordMatch(entry FeedEntry) (string, float64) {
	text := strings.ToLower(entry.Title + " " + entry.Description)
	keywords := map[string]string{
		"sql injection":     "injection",
		"command injection": "injection/command-injection",
		"cross-site script": "injection/content-injection",
		"xss":               "injection/content-injection",
		"path traversal":    "input-boundary",
		"directory traversal": "input-boundary",
		"authentication bypass": "auth-flow",
		"authorization":     "auth-flow",
		"csrf":              "auth-flow/csrf-missing",
		"information disclosure": "info-leakage",
		"sensitive data":    "info-leakage",
		"hardcoded":         "info-leakage/config-leak",
	}

	for keyword, patternPrefix := range keywords {
		if strings.Contains(text, keyword) {
			resolved := u.resolveWildcard(patternPrefix + "/*")
			if resolved != "" {
				return resolved, 0.5
			}
			return patternPrefix, 0.4
		}
	}

	return "", 0.0
}

// --- State persistence ---

func (u *Updater) statePath() string {
	return filepath.Join(u.stateDir, "state.yaml")
}

func (u *Updater) readState() (stateFile, error) {
	data, err := os.ReadFile(u.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return stateFile{SchemaVersion: "1.0"}, nil
		}
		return stateFile{}, fmt.Errorf("reading state file: %w", err)
	}

	var sf stateFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return stateFile{}, fmt.Errorf("parsing state file: %w", err)
	}

	return sf, nil
}

func (u *Updater) writeSyncState(feedID string, syncTime time.Time, count int) error {
	if err := os.MkdirAll(u.stateDir, 0o750); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	state, err := u.readState()
	if err != nil {
		state = stateFile{SchemaVersion: "1.0"}
	}

	// Build a new feeds slice with the updated entry — never mutate in place.
	newFeeds := make([]feedState, 0, len(state.Feeds)+1)
	found := false
	for _, fs := range state.Feeds {
		if fs.FeedID == feedID {
			newFeeds = append(newFeeds, feedState{
				FeedID:    feedID,
				LastSync:  syncTime,
				LastCount: count,
			})
			found = true
		} else {
			newFeeds = append(newFeeds, fs)
		}
	}
	if !found {
		newFeeds = append(newFeeds, feedState{
			FeedID:    feedID,
			LastSync:  syncTime,
			LastCount: count,
		})
	}

	updated := stateFile{
		SchemaVersion: "1.0",
		Feeds:         newFeeds,
	}

	data, err := yaml.Marshal(updated)
	if err != nil {
		return fmt.Errorf("marshalling state: %w", err)
	}

	return os.WriteFile(u.statePath(), data, 0o640)
}

func (u *Updater) countNew(feedID string, entries []FeedEntry) int {
	// Load existing incremental files to detect duplicates.
	dir := filepath.Join(u.stateDir, "incremental")
	existing := make(map[string]bool)

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		// No incremental directory yet; all entries are new.
		return len(entries)
	}

	for _, de := range dirEntries {
		if !de.IsDir() {
			name := strings.TrimSuffix(de.Name(), ".yaml")
			existing[name] = true
		}
	}

	count := 0
	for _, e := range entries {
		safe := sanitizeFilename(e.SourceID)
		if !existing[safe] {
			count++
		}
	}
	return count
}

// --- File writing ---

// incrementalFile is the YAML structure written per incremental entry.
type incrementalFile struct {
	SchemaVersion string `yaml:"schema_version"`
	Kind          string `yaml:"kind"`
	SourceID      string `yaml:"source_id"`
	Source        string `yaml:"source"`
	PatternRef    string `yaml:"pattern_ref"`
	Confidence    float64 `yaml:"confidence"`
	Status        string `yaml:"status"`
	Title         string `yaml:"title"`
	Description   string `yaml:"description"`
	Severity      string `yaml:"severity"`
	CWEs          []string `yaml:"cwes,omitempty"`
	References    []string `yaml:"references,omitempty"`
	AffectedPkg   []string `yaml:"affected_packages,omitempty"`
	FetchedAt     string `yaml:"fetched_at"`
}

func (u *Updater) writeIncrementalFile(dir string, entry IncrementalEntry) error {
	file := incrementalFile{
		SchemaVersion: "1.0",
		Kind:          entry.Type,
		SourceID:      entry.SourceID,
		Source:        entry.Entry.Source,
		PatternRef:    entry.PatternRef,
		Confidence:    entry.Confidence,
		Status:        entry.Status,
		Title:         entry.Entry.Title,
		Description:   entry.Entry.Description,
		Severity:      string(entry.Entry.Severity),
		CWEs:          entry.Entry.CWEs,
		References:    entry.Entry.References,
		AffectedPkg:   entry.Entry.AffectedPkg,
		FetchedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshalling incremental entry: %w", err)
	}

	filename := sanitizeFilename(entry.SourceID) + ".yaml"
	path := filepath.Join(dir, filename)

	return os.WriteFile(path, data, 0o640)
}

// --- HTTP helpers ---

func (u *Updater) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}

	req.Header.Set("User-Agent", "sentinella2/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB max
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}

	return body, nil
}

// --- String helpers ---

// sanitizeFilename converts an ID like "CVE-2026-1234" into a safe filename
// component by replacing non-alphanumeric characters with hyphens.
func sanitizeFilename(id string) string {
	var b strings.Builder
	b.Grow(len(id))
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

// truncate returns s trimmed to maxLen characters with an ellipsis if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
