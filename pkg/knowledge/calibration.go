package knowledge

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// calibrationFileVersion is the current JSON schema version for calibration.json.
const calibrationFileVersion = 1

// minSampleThreshold is the minimum α+β required to trust a bucket over a global prior.
const minSampleThreshold = 5

// BucketKey identifies a calibration bucket as "patternRef:fileGlob".
type BucketKey string

// NewBucketKey creates a key from pattern ref and file glob.
func NewBucketKey(patternRef, fileGlob string) BucketKey {
	return BucketKey(patternRef + ":" + fileGlob)
}

// PatternRef returns the pattern portion of the key.
// The file glob always starts with '*', so the separator is the last colon
// before the glob, enabling pattern refs that themselves contain colons.
func (k BucketKey) PatternRef() string {
	s := string(k)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s
	}
	return s[:i]
}

// FileGlob returns the file glob portion of the key.
func (k BucketKey) FileGlob() string {
	s := string(k)
	i := strings.LastIndex(s, ":")
	if i < 0 || i == len(s)-1 {
		return "*"
	}
	return s[i+1:]
}

// BetaBucket holds the Beta distribution parameters for a context bucket.
type BetaBucket struct {
	Alpha      int       `json:"alpha"`
	Beta       int       `json:"beta"`
	LastUpdate time.Time `json:"last_update"`
}

// Confidence returns the mean of the Beta distribution: α/(α+β).
func (b BetaBucket) Confidence() float64 {
	total := b.Alpha + b.Beta
	if total == 0 {
		return 0.5
	}
	return float64(b.Alpha) / float64(total)
}

// HasMinSamples returns true if α+β >= min.
func (b BetaBucket) HasMinSamples(min int) bool {
	return b.Alpha+b.Beta >= min
}

// calibrationFile is the on-disk representation of the calibration store.
type calibrationFile struct {
	Version      int                      `json:"version"`
	Buckets      map[BucketKey]BetaBucket `json:"buckets"`
	GlobalPriors map[string]BetaBucket    `json:"global_priors"` // key = patternRef
}

// CalibrationStore is a thread-safe, JSON-backed Bayesian confidence store.
// It maintains per-bucket Beta distribution parameters and falls back through a
// hierarchy of priors when a specific bucket lacks sufficient samples.
type CalibrationStore struct {
	mu   sync.RWMutex
	path string
	data calibrationFile
}

// defaultPrior is returned when no bucket or global prior is found.
var defaultPrior = BetaBucket{Alpha: 1, Beta: 1}

// OpenCalibrationStore opens an existing calibration.json at path, or creates a
// new one if the file does not exist. When priorsFS is non-nil, built-in priors
// are loaded from it and merged into the store as initial priors (without
// overwriting existing learned data).
func OpenCalibrationStore(path string, priorsFS fs.FS) (*CalibrationStore, error) {
	if path == "" {
		return nil, fmt.Errorf("open calibration store: path must not be empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("open calibration store: create directory: %w", err)
	}

	cs := &CalibrationStore{path: path}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cs.data = calibrationFile{
			Version:      calibrationFileVersion,
			Buckets:      make(map[BucketKey]BetaBucket),
			GlobalPriors: make(map[string]BetaBucket),
		}
	} else if err != nil {
		return nil, fmt.Errorf("open calibration store: read file: %w", err)
	} else {
		if err := json.Unmarshal(raw, &cs.data); err != nil {
			return nil, fmt.Errorf("open calibration store: parse json: %w", err)
		}
		if cs.data.Buckets == nil {
			cs.data.Buckets = make(map[BucketKey]BetaBucket)
		}
		if cs.data.GlobalPriors == nil {
			cs.data.GlobalPriors = make(map[string]BetaBucket)
		}
	}

	if priorsFS != nil {
		if err := cs.loadBuiltinPriors(priorsFS); err != nil {
			return nil, fmt.Errorf("open calibration store: load built-in priors: %w", err)
		}
	}

	if err := marshalAndWriteCalibration(cs.path, cs.data); err != nil {
		return nil, fmt.Errorf("open calibration store: initial save: %w", err)
	}

	return cs, nil
}

// GetBucket returns the BetaBucket for the given key, or defaultPrior if not found.
func (cs *CalibrationStore) GetBucket(key BucketKey) BetaBucket {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if b, ok := cs.data.Buckets[key]; ok {
		return b
	}
	return defaultPrior
}

// ConfidenceFor returns the calibrated confidence for the given pattern and file.
// It resolves confidence through the following hierarchy:
//  1. Exact bucket (patternRef:*.ext or compound extension glob)
//  2. Wildcard bucket (patternRef:*)
//  3. Global prior for patternRef
//  4. Default prior (α=1, β=1, confidence=0.5)
//
// If the best specific bucket has α+β < minSampleThreshold, the global prior is
// used instead (min-sample guard).
func (cs *CalibrationStore) ConfidenceFor(patternRef, relFilePath string) float64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	glob := fileGlobFor(relFilePath)
	exactKey := NewBucketKey(patternRef, glob)
	wildcardKey := NewBucketKey(patternRef, "*")

	globalPrior, hasGlobal := cs.data.GlobalPriors[patternRef]

	// Try exact bucket.
	if b, ok := cs.data.Buckets[exactKey]; ok {
		if b.HasMinSamples(minSampleThreshold) {
			return b.Confidence()
		}
		// Exact bucket exists but too few samples — fall through to global prior.
		if hasGlobal {
			return globalPrior.Confidence()
		}
		return defaultPrior.Confidence()
	}

	// Try wildcard bucket.
	if b, ok := cs.data.Buckets[wildcardKey]; ok {
		if b.HasMinSamples(minSampleThreshold) {
			return b.Confidence()
		}
		if hasGlobal {
			return globalPrior.Confidence()
		}
		return defaultPrior.Confidence()
	}

	// Fall back to global prior.
	if hasGlobal {
		return globalPrior.Confidence()
	}

	return defaultPrior.Confidence()
}

// RecordVerdict updates the appropriate bucket based on the verdict:
//   - confirmed, fixed → α += 1
//   - false_positive   → β += 1
//   - accepted, missed → no update
func (cs *CalibrationStore) RecordVerdict(patternRef, fileGlob string, verdict Verdict) {
	switch verdict {
	case VerdictConfirmed, VerdictFixed:
		// true positive — increment alpha
	case VerdictFalsePositive:
		// false positive — increment beta
	default:
		// accepted, missed — no update
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	key := NewBucketKey(patternRef, fileGlob)
	b := cs.data.Buckets[key]

	switch verdict {
	case VerdictConfirmed, VerdictFixed:
		b.Alpha++
	case VerdictFalsePositive:
		b.Beta++
	}
	b.LastUpdate = time.Now().UTC()

	updated := copyBuckets(cs.data.Buckets)
	updated[key] = b

	next := calibrationFile{
		Version:      cs.data.Version,
		Buckets:      updated,
		GlobalPriors: cs.data.GlobalPriors,
	}
	_ = marshalAndWriteCalibration(cs.path, next)
	cs.data = next
}

// ApplyTimeDecay multiplies α and β by factor for any bucket whose LastUpdate is
// older than maxAge. Both α and β are clamped to a minimum of 1.
func (cs *CalibrationStore) ApplyTimeDecay(maxAge time.Duration, factor float64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cutoff := time.Now().UTC().Add(-maxAge)
	updated := copyBuckets(cs.data.Buckets)
	changed := false

	for key, b := range updated {
		if !b.LastUpdate.IsZero() && b.LastUpdate.Before(cutoff) {
			newAlpha := int(math.Round(float64(b.Alpha) * factor))
			newBeta := int(math.Round(float64(b.Beta) * factor))
			if newAlpha < 1 {
				newAlpha = 1
			}
			if newBeta < 1 {
				newBeta = 1
			}
			updated[key] = BetaBucket{
				Alpha:      newAlpha,
				Beta:       newBeta,
				LastUpdate: b.LastUpdate,
			}
			changed = true
		}
	}

	if !changed {
		return
	}

	next := calibrationFile{
		Version:      cs.data.Version,
		Buckets:      updated,
		GlobalPriors: cs.data.GlobalPriors,
	}
	_ = marshalAndWriteCalibration(cs.path, next)
	cs.data = next
}

// Buckets returns a copy of all learned buckets.
func (cs *CalibrationStore) Buckets() map[BucketKey]BetaBucket {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	return copyBuckets(cs.data.Buckets)
}

// Save writes the current in-memory state to disk.
func (cs *CalibrationStore) Save() error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if err := marshalAndWriteCalibration(cs.path, cs.data); err != nil {
		return fmt.Errorf("save calibration: %w", err)
	}
	return nil
}

// Export returns the calibration store as JSON bytes for sharing.
func (cs *CalibrationStore) Export() ([]byte, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	raw, err := json.MarshalIndent(cs.data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("export calibration: marshal json: %w", err)
	}
	return raw, nil
}

// Import loads calibration data from raw JSON. When merge is true, α and β
// values are added to existing bucket values. When merge is false, imported
// buckets replace existing ones.
func (cs *CalibrationStore) Import(data []byte, merge bool) error {
	var imported calibrationFile
	if err := json.Unmarshal(data, &imported); err != nil {
		return fmt.Errorf("import calibration: parse json: %w", err)
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	updatedBuckets := copyBuckets(cs.data.Buckets)
	updatedGlobals := copyGlobalPriors(cs.data.GlobalPriors)

	for key, imp := range imported.Buckets {
		if merge {
			existing := updatedBuckets[key]
			updatedBuckets[key] = BetaBucket{
				Alpha:      existing.Alpha + imp.Alpha,
				Beta:       existing.Beta + imp.Beta,
				LastUpdate: latestTime(existing.LastUpdate, imp.LastUpdate),
			}
		} else {
			updatedBuckets[key] = imp
		}
	}

	for ref, imp := range imported.GlobalPriors {
		if merge {
			existing := updatedGlobals[ref]
			updatedGlobals[ref] = BetaBucket{
				Alpha:      existing.Alpha + imp.Alpha,
				Beta:       existing.Beta + imp.Beta,
				LastUpdate: latestTime(existing.LastUpdate, imp.LastUpdate),
			}
		} else {
			updatedGlobals[ref] = imp
		}
	}

	next := calibrationFile{
		Version:      cs.data.Version,
		Buckets:      updatedBuckets,
		GlobalPriors: updatedGlobals,
	}
	if err := marshalAndWriteCalibration(cs.path, next); err != nil {
		return fmt.Errorf("import calibration: save: %w", err)
	}
	cs.data = next
	return nil
}

// --- internal helpers ---

// builtinPriorFile is the top-level YAML structure for priors/builtin.yaml.
type builtinPriorFile struct {
	SchemaVersion string                   `yaml:"schema_version"`
	Kind          string                   `yaml:"kind"`
	Description   string                   `yaml:"description"`
	Buckets       map[string]builtinBucket `yaml:"buckets"`
	GlobalPriors  map[string]builtinBucket `yaml:"global_priors"`
}

type builtinBucket struct {
	Alpha int    `yaml:"alpha"`
	Beta  int    `yaml:"beta"`
	Note  string `yaml:"note"`
}

// loadBuiltinPriors reads priors/builtin.yaml from priorsFS and merges them into
// the store as initial defaults, without overwriting any existing learned data.
func (cs *CalibrationStore) loadBuiltinPriors(fsys fs.FS) error {
	data, err := fs.ReadFile(fsys, "knowledge/priors/builtin.yaml")
	if err != nil {
		return fmt.Errorf("read builtin.yaml: %w", err)
	}

	var pf builtinPriorFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse builtin.yaml: %w", err)
	}

	for rawKey, bb := range pf.Buckets {
		key := BucketKey(rawKey)
		if _, exists := cs.data.Buckets[key]; !exists {
			cs.data.Buckets[key] = BetaBucket{
				Alpha: bb.Alpha,
				Beta:  bb.Beta,
			}
		}
	}

	for ref, bb := range pf.GlobalPriors {
		if _, exists := cs.data.GlobalPriors[ref]; !exists {
			cs.data.GlobalPriors[ref] = BetaBucket{
				Alpha: bb.Alpha,
				Beta:  bb.Beta,
			}
		}
	}

	return nil
}

// fileGlobFor extracts the longest compound extension glob from a file path.
// For example: "src/auth.controller.ts" → "*.controller.ts", "query.go" → "*.go".
func fileGlobFor(path string) string {
	base := filepath.Base(path)
	// Find the first dot that's not a leading dot (hidden files).
	for i, ch := range base {
		if ch == '.' && i > 0 {
			return "*" + base[i:]
		}
	}
	return "*"
}

// marshalAndWriteCalibration atomically writes calibration data to path via
// temp file rename.
func marshalAndWriteCalibration(path string, data calibrationFile) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// copyBuckets returns a shallow copy of the buckets map.
func copyBuckets(src map[BucketKey]BetaBucket) map[BucketKey]BetaBucket {
	dst := make(map[BucketKey]BetaBucket, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// copyGlobalPriors returns a shallow copy of the global priors map.
func copyGlobalPriors(src map[string]BetaBucket) map[string]BetaBucket {
	dst := make(map[string]BetaBucket, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// latestTime returns the later of two times. Zero times are treated as the
// earliest possible time.
func latestTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if a.After(b) {
		return a
	}
	return b
}

// --- bucket split detection ---

// SplitResult describes a recommended bucket split.
type SplitResult struct {
	ParentKey  BucketKey
	ChildKey   BucketKey
	ParentConf float64
	ChildConf  float64
	Divergence float64 // |parentConf - childConf| / max(parentConf, 0.01)
}

// DetectSplits analyzes feedback entries to find wildcard buckets where
// sub-populations diverge significantly. Returns split recommendations
// where the divergence exceeds threshold (e.g. 0.3 = 30%).
// The input entries and store are NOT modified.
func (cs *CalibrationStore) DetectSplits(entries []FeedbackEntry, threshold float64) []SplitResult {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var results []SplitResult

	// 1. Find all wildcard buckets (pattern:*)
	for key, parentBucket := range cs.data.Buckets {
		if key.FileGlob() != "*" {
			continue
		}
		if !parentBucket.HasMinSamples(minSampleThreshold) {
			continue
		}

		patRef := key.PatternRef()
		parentConf := parentBucket.Confidence()

		// 2. Group feedback entries for this pattern by file extension
		extGroups := groupByExtension(entries, patRef)

		// 3. For each extension group, compute its local FP rate
		for ext, group := range extGroups {
			if len(group) < minSampleThreshold {
				continue
			}

			childKey := NewBucketKey(patRef, ext)
			// Skip if a fine-grained bucket already exists
			if _, exists := cs.data.Buckets[childKey]; exists {
				continue
			}

			childConf := computeGroupConfidence(group)
			div := math.Abs(parentConf-childConf) / math.Max(parentConf, 0.01)

			if div > threshold {
				results = append(results, SplitResult{
					ParentKey:  key,
					ChildKey:   childKey,
					ParentConf: parentConf,
					ChildConf:  childConf,
					Divergence: div,
				})
			}
		}
	}

	// Sort by divergence descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Divergence > results[j].Divergence
	})
	return results
}

// ApplySplit executes a single split: creates a child bucket from feedback data
// and adjusts the parent bucket. Returns error if parent doesn't exist.
func (cs *CalibrationStore) ApplySplit(split SplitResult, entries []FeedbackEntry) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	parent, ok := cs.data.Buckets[split.ParentKey]
	if !ok {
		return fmt.Errorf("apply split: parent bucket %s not found", split.ParentKey)
	}

	patRef := split.ParentKey.PatternRef()
	childGlob := split.ChildKey.FileGlob()

	// Count TP/FP for the child extension
	var childAlpha, childBeta int
	for _, e := range entries {
		if e.PatternRef != patRef {
			continue
		}
		ext := extractFilePattern(e.File)
		if ext != childGlob {
			continue
		}
		switch e.Verdict {
		case VerdictConfirmed, VerdictFixed:
			childAlpha++
		case VerdictFalsePositive:
			childBeta++
		}
	}

	if childAlpha == 0 && childBeta == 0 {
		return fmt.Errorf("apply split: no feedback data for %s", split.ChildKey)
	}

	// Create child bucket
	updated := copyBuckets(cs.data.Buckets)
	updated[split.ChildKey] = BetaBucket{
		Alpha:      childAlpha,
		Beta:       childBeta,
		LastUpdate: time.Now().UTC(),
	}

	// Adjust parent: subtract child counts (minimum 1)
	newAlpha := parent.Alpha - childAlpha
	if newAlpha < 1 {
		newAlpha = 1
	}
	newBeta := parent.Beta - childBeta
	if newBeta < 1 {
		newBeta = 1
	}
	updated[split.ParentKey] = BetaBucket{
		Alpha:      newAlpha,
		Beta:       newBeta,
		LastUpdate: time.Now().UTC(),
	}

	next := calibrationFile{
		Version:      cs.data.Version,
		Buckets:      updated,
		GlobalPriors: cs.data.GlobalPriors,
	}
	if err := marshalAndWriteCalibration(cs.path, next); err != nil {
		return fmt.Errorf("apply split: save: %w", err)
	}
	cs.data = next
	return nil
}

// groupByExtension groups feedback entries by their file extension pattern.
func groupByExtension(entries []FeedbackEntry, patternRef string) map[string][]FeedbackEntry {
	groups := make(map[string][]FeedbackEntry)
	for _, e := range entries {
		if e.PatternRef != patternRef {
			continue
		}
		ext := extractFilePattern(e.File)
		if ext != "" {
			groups[ext] = append(groups[ext], e)
		}
	}
	return groups
}

// computeGroupConfidence computes α/(α+β) from feedback entries in a group.
func computeGroupConfidence(entries []FeedbackEntry) float64 {
	var alpha, beta int
	for _, e := range entries {
		switch e.Verdict {
		case VerdictConfirmed, VerdictFixed:
			alpha++
		case VerdictFalsePositive:
			beta++
		}
	}
	total := alpha + beta
	if total == 0 {
		return 0.5
	}
	return float64(alpha) / float64(total)
}

// SharedCalibrationDir returns the path to the shared calibration directory.
// Default: ~/.sentinella2/calibration/
func SharedCalibrationDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("shared calibration dir: %w", err)
	}
	dir := filepath.Join(home, ".sentinella2", "calibration")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("shared calibration dir: create: %w", err)
	}
	return dir, nil
}

// LoadStackPriors loads calibration data from a shared stack-specific file.
// Only buckets NOT already present in the store are loaded (existing learned
// data is never overwritten by shared priors).
// Returns the number of buckets loaded, or 0 if no shared file exists.
func (cs *CalibrationStore) LoadStackPriors(stack TechStack) (int, error) {
	if stack.ID == "" {
		return 0, nil
	}

	dir, err := SharedCalibrationDir()
	if err != nil {
		return 0, err
	}

	sharedPath := filepath.Join(dir, stack.ID+".json")
	raw, err := os.ReadFile(sharedPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load stack priors %s: %w", stack.ID, err)
	}

	var imported calibrationFile
	if err := json.Unmarshal(raw, &imported); err != nil {
		return 0, fmt.Errorf("load stack priors %s: parse json: %w", stack.ID, err)
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	updatedBuckets := copyBuckets(cs.data.Buckets)
	updatedGlobals := copyGlobalPriors(cs.data.GlobalPriors)
	loaded := 0

	for key, b := range imported.Buckets {
		if _, exists := updatedBuckets[key]; !exists {
			updatedBuckets[key] = b
			loaded++
		}
	}
	for ref, b := range imported.GlobalPriors {
		if _, exists := updatedGlobals[ref]; !exists {
			updatedGlobals[ref] = b
		}
	}

	if loaded == 0 {
		return 0, nil
	}

	next := calibrationFile{
		Version:      cs.data.Version,
		Buckets:      updatedBuckets,
		GlobalPriors: updatedGlobals,
	}
	if err := marshalAndWriteCalibration(cs.path, next); err != nil {
		return 0, fmt.Errorf("load stack priors %s: save: %w", stack.ID, err)
	}
	cs.data = next
	return loaded, nil
}

// ExportForStack exports the current calibration data to the shared
// stack-specific file for reuse by other projects with the same stack.
func (cs *CalibrationStore) ExportForStack(stack TechStack) error {
	if stack.ID == "" {
		return fmt.Errorf("export for stack: stack ID must not be empty")
	}

	dir, err := SharedCalibrationDir()
	if err != nil {
		return err
	}

	data, err := cs.Export()
	if err != nil {
		return fmt.Errorf("export for stack %s: %w", stack.ID, err)
	}

	path := filepath.Join(dir, stack.ID+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("export for stack %s: write: %w", stack.ID, err)
	}

	return nil
}
