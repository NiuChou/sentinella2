package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// setupCrossFileFixture creates a temporary directory with files simulating
// the cross-platform anti-patterns. Returns the absolute path and a cleanup func.
func setupCrossFileFixture(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	// Platform A: independent auth client
	mkdirAndWrite(t, dir, "platform-a/src/api/client.ts", `
import axios from 'axios';

const instance = axios.create({ baseURL: '/api' });

instance.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      try {
        await refreshToken();
        return instance(error.config);
      } catch (e) {
        console.error('refresh failed', e);
        // BUG: no re-throw, no redirect
      }
    }
  }
);

export const apiClient = instance;
`)

	// Platform B: another independent auth client
	mkdirAndWrite(t, dir, "platform-b/src/api/client.ts", `
import axios from 'axios';

const api = axios.create({ baseURL: '/v2/api' });

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    if (err.response?.status === 401) {
      try {
        await refreshToken();
        return api(err.config);
      } catch (refreshError) {
        console.log('token refresh failed');
        // BUG: same catch-not-rethrow bug duplicated
      }
    }
  }
);

export default api;
`)

	// Platform C: yet another auth client
	mkdirAndWrite(t, dir, "platform-c/src/api/fetcher.ts", `
const createAuthClient = (baseURL: string) => {
  return {
    fetch: async (url: string) => {
      const resp = await fetch(baseURL + url, {
        headers: { authorization: getToken() },
      });
      if (resp.status === 401) {
        await refreshToken();
        return fetch(baseURL + url);
      }
      return resp;
    },
  };
};

export default createAuthClient;
`)

	// Platform A: rate limit config
	mkdirAndWrite(t, dir, "platform-a/config/rate-limit.yaml", `
rate_limit:
  requests_per_second: 100
  burst: 200
  excluded_paths:
    - /health
`)

	// Platform B: different rate limit config
	mkdirAndWrite(t, dir, "platform-b/config/rate-limit.yaml", `
rate_limit:
  requests_per_second: 50
  burst: 100
  excluded_paths:
    - /health
    - /auth/refresh
`)

	// Cookie TTL and JWT TTL in different files with different values
	mkdirAndWrite(t, dir, "platform-a/src/auth/cookie.ts", `
export function setAuthCookie(res: Response, token: string) {
  res.cookie('access_token', token, {
    maxAge: 900000,  // 15 minutes in ms
    httpOnly: true,
  });
}
`)

	mkdirAndWrite(t, dir, "platform-a/src/auth/jwt.ts", `
import jwt from 'jsonwebtoken';

export function signToken(payload: object) {
  return jwt.sign(payload, SECRET, {
    expiresIn: '30m',  // 30 minutes — MISMATCH with cookie maxAge
  });
}
`)

	return dir
}

func mkdirAndWrite(t *testing.T, base, relPath, content string) {
	t.Helper()
	abs := filepath.Join(base, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildTestKB(patterns []knowledge.Pattern) knowledge.KnowledgeBase {
	return knowledge.NewKnowledgeBaseForTest(patterns, nil, nil, nil, nil)
}

func TestCrossFileScanner_Duplication(t *testing.T) {
	dir := setupCrossFileFixture(t)

	pat := knowledge.Pattern{
		ID:          "cross-platform/auth-client-duplication",
		Name:        "Duplicated Auth Client",
		Description: "Multiple platforms independently implement auth client",
		Severity:    knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 2,
			CrossFile: &knowledge.CrossFileRule{
				Collect:     `interceptors\.response\.use|createAuthClient`,
				CollectFrom: []string{"**/*.ts"},
				Assert:      "unique_count > 1",
				AssertType:  "duplication",
				GroupBy:     "top_directory",
			},
		},
		Fix: knowledge.Fix{Abstract: "Extract shared auth client library"},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	result, err := scanner.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	findings := result.Findings()
	if len(findings) == 0 {
		t.Fatal("expected duplication findings, got none")
	}

	// Should have findings for duplicate groups (platform-b and platform-c)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 duplication findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.PatternRef != "cross-platform/auth-client-duplication" {
			t.Errorf("unexpected PatternRef: %s", f.PatternRef)
		}
		if f.Severity != knowledge.SeverityHigh {
			t.Errorf("unexpected Severity: %s", f.Severity)
		}
		if f.Confidence <= 0 || f.Confidence > 1 {
			t.Errorf("confidence out of range: %f", f.Confidence)
		}
	}
}

func TestCrossFileScanner_Consistency(t *testing.T) {
	// Create a fixture with inconsistent config values across service dirs.
	dir := t.TempDir()

	mkdirAndWrite(t, dir, "gateway-a/config/timeout.yaml", `
connection_timeout: 30
request_timeout: 60
`)
	mkdirAndWrite(t, dir, "gateway-b/config/timeout.yaml", `
connection_timeout: 15
request_timeout: 120
`)

	pat := knowledge.Pattern{
		ID:          "test/config-consistency",
		Name:        "Inconsistent Config Values",
		Description: "Config values differ across services",
		Severity:    knowledge.SeverityMedium,
		Detection: knowledge.Detection{
			Tier: 2,
			CrossFile: &knowledge.CrossFileRule{
				Collect:     `connection_timeout:\s*\d+`,
				CollectFrom: []string{"**/*.yaml"},
				Assert:      "values_differ",
				AssertType:  "consistency",
				GroupBy:     "none",
			},
		},
		Fix: knowledge.Fix{Abstract: "Unify config values"},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	result, err := scanner.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	findings := result.Findings()
	if len(findings) == 0 {
		t.Fatal("expected consistency finding for mismatched config values, got none")
	}

	f := findings[0]
	if f.PatternRef != "test/config-consistency" {
		t.Errorf("unexpected PatternRef: %s", f.PatternRef)
	}
	if f.Severity != knowledge.SeverityMedium {
		t.Errorf("unexpected Severity: %s", f.Severity)
	}
}

func TestCrossFileScanner_Completeness(t *testing.T) {
	dir := setupCrossFileFixture(t)

	pat := knowledge.Pattern{
		ID:          "cross-platform/incomplete-refresh-chain",
		Name:        "Incomplete Refresh Chain",
		Description: "401 handler missing re-throw or redirect",
		Severity:    knowledge.SeverityCritical,
		Detection: knowledge.Detection{
			Tier: 2,
			CrossFile: &knowledge.CrossFileRule{
				Collect:     `refreshToken|interceptors\.response\.use|status\s*===?\s*401`,
				CollectFrom: []string{"**/*.ts"},
				Assert:      "chain_has_all_of: refresh,throw_or_redirect",
				AssertType:  "completeness",
				GroupBy:     "top_directory",
			},
		},
		Fix: knowledge.Fix{Abstract: "Add re-throw and login redirect to catch blocks"},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	result, err := scanner.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	findings := result.Findings()
	// platform-a and platform-b have catch blocks without throw/redirect
	if len(findings) == 0 {
		t.Fatal("expected completeness finding for incomplete refresh chain, got none")
	}

	for _, f := range findings {
		if f.Severity != knowledge.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", f.Severity)
		}
	}
}

func TestCrossFileScanner_NoCrossFilePatterns(t *testing.T) {
	dir := t.TempDir()

	// Pattern without cross_file — should produce no findings.
	pat := knowledge.Pattern{
		ID:       "auth-flow/idor",
		Name:     "IDOR",
		Severity: knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 1,
			Rules: map[string]knowledge.RuleSet{
				"go": {Pattern: `findByID`},
			},
		},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	result, err := scanner.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings()) != 0 {
		t.Errorf("expected 0 findings for non-crossfile patterns, got %d", len(result.Findings()))
	}
}

func TestCrossFileScanner_SingleGroup_NoDuplication(t *testing.T) {
	dir := t.TempDir()

	// Only one platform — should not flag duplication.
	mkdirAndWrite(t, dir, "platform-a/src/api/client.ts", `
const instance = axios.create();
instance.interceptors.response.use(() => {}, () => {});
`)

	pat := knowledge.Pattern{
		ID:       "cross-platform/auth-client-duplication",
		Name:     "Duplicated Auth Client",
		Severity: knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 2,
			CrossFile: &knowledge.CrossFileRule{
				Collect:     `interceptors\.response\.use`,
				CollectFrom: []string{"**/*.ts"},
				Assert:      "unique_count > 1",
				AssertType:  "duplication",
				GroupBy:     "top_directory",
			},
		},
		Fix: knowledge.Fix{Abstract: "Extract shared auth client"},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	result, err := scanner.Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings()) != 0 {
		t.Errorf("expected 0 findings for single-group duplication, got %d", len(result.Findings()))
	}
}

func TestCrossFileScanner_ContextCancellation(t *testing.T) {
	dir := setupCrossFileFixture(t)

	pat := knowledge.Pattern{
		ID:       "cross-platform/auth-client-duplication",
		Severity: knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 2,
			CrossFile: &knowledge.CrossFileRule{
				Collect:     `interceptors`,
				CollectFrom: []string{"**/*.ts"},
				AssertType:  "duplication",
				GroupBy:     "top_directory",
			},
		},
	}

	kb := buildTestKB([]knowledge.Pattern{pat})
	scanner := NewCrossFileScanner(WithKnowledge(kb), WithMaxTier(2))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := scanner.Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	// Should return partial or empty results without error.
	_ = result
}

func TestDeriveGroup(t *testing.T) {
	tests := []struct {
		path    string
		groupBy string
		want    string
	}{
		{"platform-a/src/client.ts", "top_directory", "platform-a"},
		{"platform-b/api/auth.ts", "top_directory", "platform-b"},
		{"root-file.ts", "top_directory", "_root"},
		{"any/path/file.ts", "none", "_all"},
		{"any/path/file.ts", "", "_all"},
	}

	for _, tt := range tests {
		got := deriveGroup(tt.path, tt.groupBy)
		if got != tt.want {
			t.Errorf("deriveGroup(%q, %q) = %q, want %q", tt.path, tt.groupBy, got, tt.want)
		}
	}
}

func TestParseChainRequirements(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"chain_has_all_of: refresh,throw_or_redirect", []string{"refresh", "throw_or_redirect"}},
		{"chain_has_all_of: a,b,c", []string{"a", "b", "c"}},
		{"invalid", nil},
	}

	for _, tt := range tests {
		got := parseChainRequirements(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseChainRequirements(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i, v := range got {
			if v != tt.want[i] {
				t.Errorf("parseChainRequirements(%q)[%d] = %q, want %q", tt.input, i, v, tt.want[i])
			}
		}
	}
}

func TestFindMissingChainParts(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		required []string
		missing  []string
	}{
		{"both present", "refresh token and then throw error", []string{"refresh", "throw_or_redirect"}, nil},
		{"alt present", "refresh token and then redirect to login", []string{"refresh", "throw_or_redirect"}, nil},
		{"none present", "just logs the error", []string{"refresh", "throw_or_redirect"}, []string{"refresh", "throw_or_redirect"}},
		{"partial missing", "has refresh but logs only", []string{"refresh", "throw_or_redirect"}, []string{"throw_or_redirect"}},
		// Word boundary: "refreshInterval" should NOT match "refresh"
		{"word boundary prevents substring match", "set refreshInterval to 30s", []string{"refresh", "throw_or_redirect"}, []string{"refresh", "throw_or_redirect"}},
		// Word boundary: standalone "throw" should still match
		{"standalone word matches", "catch(e) { throw e; }", []string{"throw"}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findMissingChainParts(tt.text, tt.required)
			if len(got) != len(tt.missing) {
				t.Errorf("findMissingChainParts(%q) = %v, want %v", tt.text, got, tt.missing)
			}
		})
	}
}
