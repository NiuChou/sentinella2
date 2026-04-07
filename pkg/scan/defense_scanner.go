package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/perseworks/sentinella2/internal/matcher"
	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// LayerStatus represents the assessment outcome for a defense layer or check.
type LayerStatus string

const (
	LayerPass    LayerStatus = "PASS"
	LayerWarning LayerStatus = "WARNING"
	LayerFail    LayerStatus = "FAIL"
	LayerUnknown LayerStatus = "UNKNOWN"
)

// LayerResult holds the immutable defense layer assessment results.
type LayerResult struct {
	layers []LayerAssessment
}

// Layers returns a copy of all layer assessments.
func (r LayerResult) Layers() []LayerAssessment {
	out := make([]LayerAssessment, len(r.layers))
	copy(out, r.layers)
	return out
}

// OverallStatus returns the worst status across all layers.
func (r LayerResult) OverallStatus() LayerStatus {
	worst := LayerPass
	for _, la := range r.layers {
		if statusSeverity(la.Status) > statusSeverity(worst) {
			worst = la.Status
		}
	}
	return worst
}

// LayerAssessment holds the assessment for a single defense layer.
type LayerAssessment struct {
	Layer  knowledge.DefenseLayer
	Status LayerStatus
	Checks []CheckResult
}

// CheckResult holds the assessment for a single check within a layer.
type CheckResult struct {
	Check  knowledge.LayerCheck
	Status LayerStatus
	Detail string
}

// ScanDefenseLayers evaluates the 6-layer defense-in-depth posture of
// the target directory against the checks defined in the knowledge base.
// Only Tier 1 checks (file-pattern based) are evaluated deterministically;
// higher-tier checks are marked as UNKNOWN.
func ScanDefenseLayers(
	ctx context.Context,
	targetDir string,
	kb knowledge.KnowledgeBase,
) (LayerResult, error) {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return LayerResult{}, fmt.Errorf("resolving target directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return LayerResult{}, fmt.Errorf("accessing target directory: %w", err)
	}
	if !info.IsDir() {
		return LayerResult{}, fmt.Errorf("target path %q is not a directory", absDir)
	}

	layers := kb.DefenseLayers()
	regexM := matcher.NewRegexMatcher()
	globM := matcher.NewGlobMatcher()

	assessments := make([]LayerAssessment, 0, len(layers))

	for _, layer := range layers {
		select {
		case <-ctx.Done():
			return LayerResult{}, ctx.Err()
		default:
		}

		la := assessLayer(ctx, absDir, layer, regexM, globM)
		assessments = append(assessments, la)
	}

	return LayerResult{layers: assessments}, nil
}

// assessLayer evaluates all checks in a single defense layer.
func assessLayer(
	ctx context.Context,
	absDir string,
	layer knowledge.DefenseLayer,
	regexM *matcher.RegexMatcher,
	globM *matcher.GlobMatcher,
) LayerAssessment {
	checks := make([]CheckResult, 0, len(layer.Checks))
	worst := LayerPass

	for _, check := range layer.Checks {
		select {
		case <-ctx.Done():
			checks = append(checks, CheckResult{
				Check:  check,
				Status: LayerUnknown,
				Detail: "scan cancelled",
			})
			continue
		default:
		}

		cr := assessCheck(absDir, check, regexM, globM)
		checks = append(checks, cr)

		if statusSeverity(cr.Status) > statusSeverity(worst) {
			worst = cr.Status
		}
	}

	return LayerAssessment{
		Layer:  layer,
		Status: worst,
		Checks: checks,
	}
}

// assessCheck evaluates a single defense layer check by searching for
// the positive pattern in files matching the check's file globs.
func assessCheck(
	absDir string,
	check knowledge.LayerCheck,
	regexM *matcher.RegexMatcher,
	globM *matcher.GlobMatcher,
) CheckResult {
	// Higher-tier checks require structural or semantic analysis.
	if check.Tier > 1 {
		return CheckResult{
			Check:  check,
			Status: LayerUnknown,
			Detail: fmt.Sprintf("tier %d check requires advanced analysis", check.Tier),
		}
	}

	det := check.Detection
	if det.Pattern == "" || len(det.Files) == 0 {
		return CheckResult{
			Check:  check,
			Status: LayerUnknown,
			Detail: "no detection pattern or file globs defined",
		}
	}

	matchingFiles := findMatchingFiles(absDir, det.Files, globM)
	if len(matchingFiles) == 0 {
		return CheckResult{
			Check:  check,
			Status: LayerWarning,
			Detail: "no configuration files found matching " + fmt.Sprintf("%v", det.Files),
		}
	}

	positiveFound := false
	negativeFound := false

	for _, fpath := range matchingFiles {
		content, err := readFileBounded(fpath)
		if err != nil {
			continue
		}

		posMatches, err := regexM.Match(det.Pattern, content)
		if err != nil {
			continue
		}
		if len(posMatches) > 0 {
			positiveFound = true
		}

		if det.NegativePattern != "" {
			negMatches, err := regexM.Match(det.NegativePattern, content)
			if err != nil {
				continue
			}
			if len(negMatches) > 0 {
				negativeFound = true
			}
		}
	}

	return classifyCheckResult(check, positiveFound, negativeFound)
}

// classifyCheckResult determines the status based on positive and negative
// pattern matches. A positive match means the security control is present;
// a negative match indicates a misconfiguration weakening that control.
func classifyCheckResult(
	check knowledge.LayerCheck,
	positiveFound bool,
	negativeFound bool,
) CheckResult {
	switch {
	case positiveFound && !negativeFound:
		return CheckResult{
			Check:  check,
			Status: LayerPass,
			Detail: "security control detected and properly configured",
		}
	case positiveFound && negativeFound:
		return CheckResult{
			Check:  check,
			Status: LayerWarning,
			Detail: "security control detected but misconfiguration found",
		}
	default:
		return CheckResult{
			Check:  check,
			Status: LayerFail,
			Detail: "security control not detected in scanned files",
		}
	}
}

// findMatchingFiles walks the directory and returns paths matching any
// of the given glob patterns.
func findMatchingFiles(
	absDir string,
	fileGlobs []string,
	globM *matcher.GlobMatcher,
) []string {
	var matched []string
	_ = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return nil
		}
		if globM.MatchPath(rel, fileGlobs) {
			matched = append(matched, path)
		}
		return nil
	})
	return matched
}

// statusSeverity maps a LayerStatus to a numeric severity for comparison.
func statusSeverity(s LayerStatus) int {
	switch s {
	case LayerPass:
		return 0
	case LayerUnknown:
		return 1
	case LayerWarning:
		return 2
	case LayerFail:
		return 3
	default:
		return 0
	}
}
