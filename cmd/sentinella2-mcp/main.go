// Command sentinella2-mcp is an MCP (Model Context Protocol) server that
// exposes sentinella2's scanning capabilities over JSON-RPC 2.0 via stdio.
// Any IDE supporting MCP (Claude Code, Cursor, VS Code + Continue, etc.)
// can use this server to run security scans.
package main

import (
	"fmt"
	"os"

	sentinella2 "github.com/perseworks/sentinella2"
	"github.com/perseworks/sentinella2/pkg/knowledge"
)

func main() {
	kb, err := knowledge.LoadFromFS(sentinella2.KnowledgeFS, "knowledge")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinella2-mcp: failed to load knowledge base: %v\n", err)
		os.Exit(1)
	}

	server := NewMCPServer(kb)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "sentinella2-mcp: %v\n", err)
		os.Exit(1)
	}
}
