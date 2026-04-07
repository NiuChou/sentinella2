package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider implements Provider using the OpenAI-compatible Chat
// Completions API. This covers OpenAI, Anthropic (via compatibility layer),
// ZhipuAI GLM, Ollama, and any provider with the same API shape.
type OpenAIProvider struct {
	cfg    Config
	client *http.Client
}

func newOpenAIProvider(cfg Config) (*OpenAIProvider, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required for openai-compatible provider")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("model is required for openai-compatible provider")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("api_key is required for openai-compatible provider")
	}

	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	return &OpenAIProvider{cfg: cfg, client: client}, nil
}

// Name returns "openai-compatible".
func (p *OpenAIProvider) Name() string {
	return "openai-compatible"
}

// Audit sends the code and pattern to the LLM for analysis and returns parsed findings.
func (p *OpenAIProvider) Audit(ctx context.Context, req AuditRequest) (AuditResponse, error) {
	userPrompt := buildUserPrompt(req)
	chatReq := buildChatRequest(p.cfg.Model, req.SystemPrompt, userPrompt)

	body, err := json.Marshal(chatReq)
	if err != nil {
		return AuditResponse{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	rawResp, err := p.doRequest(ctx, body)
	if err != nil {
		return AuditResponse{}, err
	}

	findings, err := parseFindings(rawResp)
	if err != nil {
		// Return raw response even if parsing fails, for debugging.
		return AuditResponse{Raw: rawResp}, fmt.Errorf("failed to parse findings: %w", err)
	}

	return AuditResponse{Findings: findings, Raw: rawResp}, nil
}

func (p *OpenAIProvider) doRequest(ctx context.Context, body []byte) (string, error) {
	url := strings.TrimRight(p.cfg.BaseURL, "/") + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	content, err := extractContent(respBody)
	if err != nil {
		return "", fmt.Errorf("failed to extract content from response: %w", err)
	}

	return content, nil
}

// --- Chat Completions API types ---

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []chatChoice `json:"choices"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

func buildChatRequest(model, systemPrompt, userPrompt string) chatRequest {
	return chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1,
	}
}

func buildUserPrompt(req AuditRequest) string {
	return fmt.Sprintf(
		"Analyze the following %s code for vulnerability pattern: %s\n\n"+
			"Respond with a JSON array of findings. Each finding must have: "+
			"pattern_ref, severity (CRITICAL/HIGH/MEDIUM/LOW), file, line, "+
			"description, fix_suggestion, confidence (0.0-1.0).\n\n"+
			"If no vulnerabilities are found, respond with an empty array: []\n\n"+
			"Code:\n```\n%s\n```",
		req.Language, req.Pattern, req.CodeContext,
	)
}

func extractContent(body []byte) (string, error) {
	var resp chatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	return resp.Choices[0].Message.Content, nil
}

func parseFindings(raw string) ([]AuditFinding, error) {
	// The LLM may wrap the JSON in markdown code fences; strip them.
	cleaned := stripCodeFences(raw)

	var findings []AuditFinding
	if err := json.Unmarshal([]byte(cleaned), &findings); err != nil {
		return nil, fmt.Errorf("failed to parse findings JSON: %w", err)
	}
	return findings, nil
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
	}
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSuffix(s, "```")
	}
	return strings.TrimSpace(s)
}
