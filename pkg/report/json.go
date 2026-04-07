package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/perseworks/sentinella2/pkg/scan"
)

// JSONReporter outputs structured JSON for CI/CD pipelines.
type JSONReporter struct{}

// jsonOutput is the top-level JSON envelope for scan results.
type jsonOutput struct {
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

// jsonSummary is the JSON representation of scan.Summary.
type jsonSummary struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Total    int    `json:"total"`
	Files    int    `json:"files"`
	Duration string `json:"duration"`
}

// jsonFinding is the JSON representation of scan.Finding.
type jsonFinding struct {
	RuleID      string `json:"rule_id"`
	PatternRef  string `json:"pattern_ref"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Message     string `json:"message"`
	MatchedText string `json:"matched_text,omitempty"`
	FixHint     string `json:"fix_hint,omitempty"`
}

// jsonLayerOutput is the top-level JSON envelope for layer assessments.
type jsonLayerOutput struct {
	DefenseLayers []jsonLayerAssessment `json:"defense_layers"`
}

// jsonLayerAssessment is the JSON representation of scan.LayerAssessment.
type jsonLayerAssessment struct {
	LayerID string            `json:"layer_id"`
	Layer   string            `json:"layer"`
	Status  string            `json:"status"`
	Checks  []jsonCheckResult `json:"checks"`
}

// jsonCheckResult is the JSON representation of scan.CheckResult.
type jsonCheckResult struct {
	CheckID string `json:"check_id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Report writes findings as structured JSON.
func (j *JSONReporter) Report(w io.Writer, result scan.Result) error {
	output := toJSONOutput(result)
	return writeJSON(w, output)
}

// ReportLayers writes layer assessments as structured JSON.
func (j *JSONReporter) ReportLayers(w io.Writer, result scan.LayerResult) error {
	output := toJSONLayerOutput(result)
	return writeJSON(w, output)
}

func toJSONOutput(result scan.Result) jsonOutput {
	s := result.Summary()
	findings := result.Findings()

	jFindings := make([]jsonFinding, len(findings))
	for i, f := range findings {
		jFindings[i] = jsonFinding{
			RuleID:      f.RuleID,
			PatternRef:  f.PatternRef,
			Severity:    string(f.Severity),
			File:        f.File,
			Line:        f.Line,
			Column:      f.Column,
			Message:     f.Message,
			MatchedText: f.MatchedText,
			FixHint:     f.FixHint,
		}
	}

	return jsonOutput{
		Summary: jsonSummary{
			Critical: s.Critical,
			High:     s.High,
			Medium:   s.Medium,
			Low:      s.Low,
			Total:    s.Total,
			Files:    s.Files,
			Duration: s.Duration.String(),
		},
		Findings: jFindings,
	}
}

func toJSONLayerOutput(result scan.LayerResult) jsonLayerOutput {
	layers := result.Layers()
	jLayers := make([]jsonLayerAssessment, len(layers))

	for i, la := range layers {
		checks := make([]jsonCheckResult, len(la.Checks))
		for ci, c := range la.Checks {
			checks[ci] = jsonCheckResult{
				CheckID: c.Check.ID,
				Name:    c.Check.Name,
				Status:  string(c.Status),
				Detail:  c.Detail,
			}
		}
		jLayers[i] = jsonLayerAssessment{
			LayerID: la.Layer.ID,
			Layer:   la.Layer.Name,
			Status:  string(la.Status),
			Checks:  checks,
		}
	}

	return jsonLayerOutput{DefenseLayers: jLayers}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}
