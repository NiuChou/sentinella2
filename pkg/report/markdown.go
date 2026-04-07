package report

import (
	"fmt"
	"io"

	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/scan"
)

// MarkdownReporter outputs formatted Markdown suitable for GitHub PRs or Notion.
type MarkdownReporter struct{}

// Report writes findings as a Markdown document with severity sections.
func (m *MarkdownReporter) Report(w io.Writer, result scan.Result) error {
	summary := result.Summary()

	if err := writeMDHeader(w, summary); err != nil {
		return fmt.Errorf("failed to write markdown header: %w", err)
	}

	if err := writeMDSummaryTable(w, summary); err != nil {
		return fmt.Errorf("failed to write summary table: %w", err)
	}

	for _, sev := range knowledge.ValidSeverities() {
		findings := result.FindingsBySeverity(sev)
		if len(findings) == 0 {
			continue
		}
		if err := writeMDSeveritySection(w, sev, findings); err != nil {
			return fmt.Errorf("failed to write %s section: %w", sev, err)
		}
	}

	return nil
}

// ReportLayers writes layer assessments as a Markdown document with tables.
func (m *MarkdownReporter) ReportLayers(w io.Writer, result scan.LayerResult) error {
	if _, err := fmt.Fprintln(w, "## Defense Layer Assessment"); err != nil {
		return fmt.Errorf("failed to write layer header: %w", err)
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	for _, layer := range result.Layers() {
		if err := writeMDLayerSection(w, layer); err != nil {
			return fmt.Errorf("failed to write layer %s: %w", layer.Layer.Name, err)
		}
	}
	return nil
}

func writeMDHeader(w io.Writer, summary scan.Summary) error {
	_, err := fmt.Fprintf(w, "# sentinella2 Scan Results\n\nScanned **%d** files in %s\n\n",
		summary.Files, summary.Duration)
	return err
}

func writeMDSummaryTable(w io.Writer, s scan.Summary) error {
	lines := []string{
		"## Summary\n",
		"| Severity | Count |",
		"|----------|-------|",
		fmt.Sprintf("| CRITICAL | %d |", s.Critical),
		fmt.Sprintf("| HIGH | %d |", s.High),
		fmt.Sprintf("| MEDIUM | %d |", s.Medium),
		fmt.Sprintf("| LOW | %d |", s.Low),
		fmt.Sprintf("| **Total** | **%d** |", s.Total),
		"",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func writeMDSeveritySection(
	w io.Writer,
	sev knowledge.Severity,
	findings []scan.Finding,
) error {
	emoji := severityEmoji(sev)
	if _, err := fmt.Fprintf(w, "## %s %s (%d)\n\n", emoji, sev, len(findings)); err != nil {
		return err
	}

	for _, f := range findings {
		if err := writeMDFinding(w, f); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(w)
	return err
}

func writeMDFinding(w io.Writer, f scan.Finding) error {
	_, err := fmt.Fprintf(w, "- **`%s`** `%s:%d` \u2014 %s\n",
		f.RuleID, f.File, f.Line, f.Message)
	if err != nil {
		return err
	}

	if f.FixHint != "" {
		_, err = fmt.Fprintf(w, "  - Fix: %s\n", f.FixHint)
	}
	return err
}

func writeMDLayerSection(w io.Writer, layer scan.LayerAssessment) error {
	emoji := layerStatusEmoji(layer.Status)
	if _, err := fmt.Fprintf(w, "### %s %s\n\n", emoji, layer.Layer.Name); err != nil {
		return err
	}

	if len(layer.Checks) == 0 {
		_, err := fmt.Fprintln(w, "No checks defined.\n")
		return err
	}

	if _, err := fmt.Fprintln(w, "| Check | Status | Detail |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|-------|--------|--------|"); err != nil {
		return err
	}

	for _, c := range layer.Checks {
		checkEmoji := layerStatusEmoji(c.Status)
		if _, err := fmt.Fprintf(w, "| %s | %s %s | %s |\n",
			c.Check.Name, checkEmoji, c.Status, c.Detail); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

func severityEmoji(sev knowledge.Severity) string {
	switch sev {
	case knowledge.SeverityCritical:
		return "\U0001f6d1" // stop sign
	case knowledge.SeverityHigh:
		return "\u26a0\ufe0f" // warning
	case knowledge.SeverityMedium:
		return "\U0001f535" // blue circle
	case knowledge.SeverityLow:
		return "\u2139\ufe0f" // info
	default:
		return ""
	}
}

func layerStatusEmoji(status scan.LayerStatus) string {
	switch status {
	case scan.LayerPass:
		return "\u2705" // green check
	case scan.LayerWarning:
		return "\u26a0\ufe0f" // warning
	case scan.LayerFail:
		return "\u274c" // red X
	case scan.LayerUnknown:
		return "\u2753" // question mark
	default:
		return ""
	}
}
