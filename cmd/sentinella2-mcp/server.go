package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// serverVersion is the reported MCP server version.
const serverVersion = "0.1.0"

// protocolVersion is the MCP protocol version this server implements.
const protocolVersion = "2024-11-05"

// --- JSON-RPC 2.0 types ---

// JSONRPCRequest represents an incoming JSON-RPC 2.0 request or notification.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError holds a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// --- MCP content types ---

// ContentBlock represents an MCP tool result content block.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult is the result payload returned from a tools/call response.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ToolCallParams holds the parsed parameters from a tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// --- MCP Server ---

// MCPServer handles MCP protocol communication over stdio. It is
// constructed once and its state (the knowledge base) is immutable.
type MCPServer struct {
	kb          knowledge.KnowledgeBase
	scanner     *bufio.Scanner
	writer      io.Writer
	feedbackDir string
	registryDir string
}

// NewMCPServer creates a server that reads JSON-RPC messages from stdin
// and writes responses to stdout. Feedback and registry data are stored
// under ~/.sentinella2/.
func NewMCPServer(kb knowledge.KnowledgeBase) *MCPServer {
	scanner := bufio.NewScanner(os.Stdin)
	// MCP messages can be large; allow up to 10 MB per line.
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	dataDir := defaultDataDir()

	return &MCPServer{
		kb:          kb,
		scanner:     scanner,
		writer:      os.Stdout,
		feedbackDir: filepath.Join(dataDir, "feedback"),
		registryDir: filepath.Join(dataDir, "registries"),
	}
}

// defaultDataDir returns the base directory for sentinella2 user data.
// It uses $SENTINELLA2_DATA_DIR if set, otherwise ~/.sentinella2.
func defaultDataDir() string {
	if dir := os.Getenv("SENTINELLA2_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to current directory if home is unavailable.
		return ".sentinella2"
	}
	return filepath.Join(home, ".sentinella2")
}

// Run processes JSON-RPC messages from stdin until EOF or an
// unrecoverable error. Returns nil on clean EOF shutdown.
func (s *MCPServer) Run() error {
	for s.scanner.Scan() {
		line := s.scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		s.handleMessage(line)
	}

	if err := s.scanner.Err(); err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	return nil
}

// handleMessage parses a single JSON-RPC line and dispatches to the
// appropriate handler. Parse errors produce a JSON-RPC error response.
func (s *MCPServer) handleMessage(data []byte) {
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		s.sendError(nil, codeParseError, "failed to parse JSON-RPC request")
		return
	}

	// Notifications (no id) do not get a response.
	if isNotification(req) {
		s.logf("notification received: %s", req.Method)
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(req.ID)
	case "tools/list":
		s.handleToolsList(req.ID)
	case "tools/call":
		s.handleToolsCall(req.ID, req.Params)
	default:
		s.sendError(req.ID, codeMethodNotFound,
			fmt.Sprintf("method not found: %s", req.Method))
	}
}

// handleInitialize responds with server capabilities and info.
func (s *MCPServer) handleInitialize(id json.RawMessage) {
	result := map[string]interface{}{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "sentinella2",
			"version": serverVersion,
		},
	}
	s.sendResult(id, result)
}

// handleToolsList responds with the catalog of available MCP tools.
func (s *MCPServer) handleToolsList(id json.RawMessage) {
	tools := buildToolDefinitions()
	result := map[string]interface{}{
		"tools": tools,
	}
	s.sendResult(id, result)
}

// handleToolsCall dispatches a tool invocation to the correct executor.
func (s *MCPServer) handleToolsCall(id json.RawMessage, params json.RawMessage) {
	var call ToolCallParams
	if err := json.Unmarshal(params, &call); err != nil {
		s.sendError(id, codeInvalidParams,
			fmt.Sprintf("invalid tools/call params: %v", err))
		return
	}

	text, execErr := s.dispatchTool(call.Name, call.Arguments)
	if execErr != nil {
		result := ToolCallResult{
			Content: []ContentBlock{{Type: "text", Text: execErr.Error()}},
			IsError: true,
		}
		s.sendResult(id, result)
		return
	}

	result := ToolCallResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
	}
	s.sendResult(id, result)
}

// dispatchTool routes to the correct tool executor by name.
func (s *MCPServer) dispatchTool(
	name string,
	args map[string]interface{},
) (string, error) {
	switch name {
	case "sentinella2_scan":
		return s.executeScan(args)
	case "sentinella2_check_layers":
		return s.executeCheckLayers(args)
	case "sentinella2_list_patterns":
		return s.executeListPatterns(args)
	case "sentinella2_get_case":
		return s.executeGetCase(args)
	case "sentinella2_kb_feedback":
		return s.executeKBFeedback(args)
	case "sentinella2_kb_stats":
		return s.executeKBStats(args)
	case "sentinella2_kb_tune":
		return s.executeKBTune(args)
	case "sentinella2_kb_sources":
		return s.executeKBSources(args)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// --- Response helpers ---

// sendResult writes a successful JSON-RPC response to stdout.
func (s *MCPServer) sendResult(id json.RawMessage, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeResponse(resp)
}

// sendError writes a JSON-RPC error response to stdout.
func (s *MCPServer) sendError(id json.RawMessage, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	}
	s.writeResponse(resp)
}

// writeResponse marshals a response and writes it as a single line to stdout.
func (s *MCPServer) writeResponse(resp JSONRPCResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		s.logf("failed to marshal response: %v", err)
		return
	}
	// MCP uses newline-delimited JSON over stdio.
	_, _ = fmt.Fprintf(s.writer, "%s\n", data)
}

// logf writes diagnostic messages to stderr (never stdout, which is
// reserved for JSON-RPC protocol traffic).
func (s *MCPServer) logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "sentinella2-mcp: "+format+"\n", args...)
}

// isNotification returns true if the request has no id field, meaning
// it is a JSON-RPC notification that should not receive a response.
func isNotification(req JSONRPCRequest) bool {
	return req.ID == nil || string(req.ID) == "null"
}
