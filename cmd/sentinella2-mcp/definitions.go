package main

// buildToolDefinitions returns the MCP tool catalog. Each entry describes
// a tool's name, description, and JSON Schema for its input parameters.
// This function is pure and returns a new slice on every call.
func buildToolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name": "sentinella2_scan",
			"description": "Run Tier 1 deterministic security scan on a project directory. " +
				"Finds hardcoded secrets, misconfigurations, and common vulnerability " +
				"patterns using regex matching. No LLM required.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the project directory to scan",
					},
					"format": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"text", "json", "markdown"},
						"default":     "text",
						"description": "Output format for scan results",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			"name": "sentinella2_check_layers",
			"description": "Evaluate 6-layer defense-in-depth posture of a project. " +
				"Checks: Ingress TLS, Isolation, Hardening, Access Control, " +
				"Data Protection, Tamper Detection.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the project directory to assess",
					},
					"format": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"text", "json", "markdown"},
						"default":     "text",
						"description": "Output format for layer assessment results",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			"name": "sentinella2_list_patterns",
			"description": "List all vulnerability detection patterns in the knowledge " +
				"base with their severity, tier, and OWASP mapping.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"severity": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "all"},
						"default":     "all",
						"description": "Filter patterns by severity level",
					},
					"tier": map[string]interface{}{
						"type":        "integer",
						"enum":        []int{0, 1, 2, 3},
						"default":     0,
						"description": "Filter by detection tier (0 = all tiers)",
					},
				},
			},
		},
		{
			"name": "sentinella2_get_case",
			"description": "Get detailed information about a specific vulnerability " +
				"case from the knowledge base, including description, fix, and lesson learned.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Case ID (e.g., 'C1', 'H6', 'M3')",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			"name": "sentinella2_kb_feedback",
			"description": "Record feedback for a scan finding. Marks a finding as " +
				"confirmed, false_positive, or missed to improve future scan accuracy.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"finding_id": map[string]interface{}{
						"type":        "string",
						"description": "Unique identifier of the scan finding",
					},
					"verdict": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"confirmed", "false_positive", "missed"},
						"description": "Assessment of the finding: confirmed (true positive), false_positive, or missed (finding was not detected)",
					},
					"reason": map[string]interface{}{
						"type":        "string",
						"description": "Optional explanation for the verdict",
					},
					"file": map[string]interface{}{
						"type":        "string",
						"description": "File path where the finding was reported",
					},
					"line": map[string]interface{}{
						"type":        "integer",
						"description": "Line number where the finding was reported",
					},
				},
				"required": []string{"finding_id", "verdict"},
			},
		},
		{
			"name": "sentinella2_kb_stats",
			"description": "Show feedback statistics for vulnerability patterns. " +
				"Displays confirmation rates, false positive rates, and total feedback counts.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pattern": map[string]interface{}{
						"type":        "string",
						"description": "Filter to a specific pattern ID (e.g., 'hardcoded-secret'). Omit to see all patterns.",
					},
				},
			},
		},
		{
			"name": "sentinella2_kb_tune",
			"description": "Run feedback-driven rule tuning. Analyzes accumulated feedback " +
				"to adjust pattern severity, confidence, and false positive hints. " +
				"Dry run by default; set dry_run=false to apply changes.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dry_run": map[string]interface{}{
						"type":        "boolean",
						"default":     true,
						"description": "If true (default), show proposed changes without applying them",
					},
				},
			},
		},
		{
			"name": "sentinella2_kb_sources",
			"description": "List registered external knowledge sources. Shows community " +
				"pattern repositories and their enabled/disabled status.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}
