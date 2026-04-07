// Package report provides formatters that render scan results in various output
// formats. All reporters implement the Reporter interface and are stateless.
package report

import (
	"fmt"
	"io"

	"github.com/perseworks/sentinella2/pkg/scan"
)

// Reporter formats scan results for output.
type Reporter interface {
	// Report writes vulnerability findings to w.
	Report(w io.Writer, result scan.Result) error
	// ReportLayers writes defense layer assessments to w.
	ReportLayers(w io.Writer, result scan.LayerResult) error
}

// Format represents an output format.
type Format string

const (
	FormatText     Format = "text"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// ValidFormats returns all supported output formats.
func ValidFormats() []Format {
	return []Format{FormatText, FormatJSON, FormatMarkdown}
}

// ParseFormat converts a string to a Format, returning an error for unknown values.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatMarkdown:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown format %q: valid formats are text, json, markdown", s)
	}
}

// New creates a Reporter for the given format.
func New(format Format) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatMarkdown:
		return &MarkdownReporter{}
	default:
		return &TextReporter{}
	}
}
