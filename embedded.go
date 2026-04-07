// Package sentinella2 provides the embedded knowledge base filesystem.
// The knowledge directory is embedded at build time via go:embed so the
// binary is self-contained with no external file dependencies.
package sentinella2

import "embed"

//go:embed all:knowledge
var KnowledgeFS embed.FS
