package report

import (
	"fmt"
	"io"

	"github.com/perseworks/sentinella2/pkg/knowledge"
	"github.com/perseworks/sentinella2/pkg/scan"
)

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
)

// TextReporter outputs human-readable colored text to the terminal.
type TextReporter struct{}

// Report writes findings grouped by severity with ANSI color coding.
func (t *TextReporter) Report(w io.Writer, result scan.Result) error {
	summary := result.Summary()

	if err := writeHeader(w, summary); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, sev := range knowledge.ValidSeverities() {
		findings := result.FindingsBySeverity(sev)
		if len(findings) == 0 {
			continue
		}
		if err := writeSeverityGroup(w, sev, findings); err != nil {
			return fmt.Errorf("failed to write %s findings: %w", sev, err)
		}
	}

	return writeSummaryFooter(w, summary)
}

// ReportLayers writes the defense layer assessment with status indicators.
func (t *TextReporter) ReportLayers(w io.Writer, result scan.LayerResult) error {
	if _, err := fmt.Fprintf(w, "\n%s%sDefense Layer Assessment%s\n\n",
		colorBold, colorBlue, colorReset); err != nil {
		return fmt.Errorf("failed to write layer header: %w", err)
	}

	for _, layer := range result.Layers() {
		if err := writeLayerAssessment(w, layer); err != nil {
			return fmt.Errorf("failed to write layer %s: %w", layer.Layer.Name, err)
		}
	}
	return nil
}

func writeHeader(w io.Writer, summary scan.Summary) error {
	_, err := fmt.Fprintf(w, "\n%s%ssentinella2 Scan Results%s\n",
		colorBold, colorBlue, colorReset)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "Scanned %d files in %s\n\n",
		summary.Files, summary.Duration)
	return err
}

func writeSeverityGroup(w io.Writer, sev knowledge.Severity, findings []scan.Finding) error {
	color := severityColor(sev)
	_, err := fmt.Fprintf(w, "%s%s%s: %d finding(s)%s\n",
		colorBold, color, sev, len(findings), colorReset)
	if err != nil {
		return err
	}

	for _, f := range findings {
		if err := writeFinding(w, f, color); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

func writeFinding(w io.Writer, f scan.Finding, color string) error {
	_, err := fmt.Fprintf(w, "  %s[%s]%s %s:%d \u2014 %s\n",
		color, f.RuleID, colorReset, f.File, f.Line, f.Message)
	if err != nil {
		return err
	}

	if f.FixHint != "" {
		_, err = fmt.Fprintf(w, "    %sfix: %s%s\n", colorGray, f.FixHint, colorReset)
	}
	return err
}

func writeSummaryFooter(w io.Writer, s scan.Summary) error {
	_, err := fmt.Fprintf(w,
		"%s%sSummary%s: %s%d critical%s, %s%d high%s, %s%d medium%s, %s%d low%s (%d total)\n",
		colorBold, colorBlue, colorReset,
		colorRed, s.Critical, colorReset,
		colorYellow, s.High, colorReset,
		colorBlue, s.Medium, colorReset,
		colorGray, s.Low, colorReset,
		s.Total,
	)
	return err
}

func writeLayerAssessment(w io.Writer, layer scan.LayerAssessment) error {
	indicator := statusIndicator(layer.Status)
	color := statusColor(layer.Status)
	_, err := fmt.Fprintf(w, "  %s%s%s %s\n", color, indicator, colorReset, layer.Layer.Name)
	if err != nil {
		return err
	}

	for _, check := range layer.Checks {
		if err := writeCheckResult(w, check); err != nil {
			return err
		}
	}
	return nil
}

func writeCheckResult(w io.Writer, check scan.CheckResult) error {
	indicator := statusIndicator(check.Status)
	color := statusColor(check.Status)
	_, err := fmt.Fprintf(w, "    %s%s%s %s", color, indicator, colorReset, check.Check.Name)
	if err != nil {
		return err
	}

	if check.Detail != "" {
		_, err = fmt.Fprintf(w, " \u2014 %s%s%s", colorGray, check.Detail, colorReset)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

func severityColor(sev knowledge.Severity) string {
	switch sev {
	case knowledge.SeverityCritical:
		return colorRed
	case knowledge.SeverityHigh:
		return colorYellow
	case knowledge.SeverityMedium:
		return colorBlue
	case knowledge.SeverityLow:
		return colorGray
	default:
		return colorReset
	}
}

func statusIndicator(status scan.LayerStatus) string {
	switch status {
	case scan.LayerPass:
		return "\u2713 PASS"
	case scan.LayerWarning:
		return "\u26a0 WARNING"
	case scan.LayerFail:
		return "\u2717 FAIL"
	case scan.LayerUnknown:
		return "? UNKNOWN"
	default:
		return "? UNKNOWN"
	}
}

func statusColor(status scan.LayerStatus) string {
	switch status {
	case scan.LayerPass:
		return colorGreen
	case scan.LayerWarning:
		return colorYellow
	case scan.LayerFail:
		return colorRed
	case scan.LayerUnknown:
		return colorGray
	default:
		return colorReset
	}
}
