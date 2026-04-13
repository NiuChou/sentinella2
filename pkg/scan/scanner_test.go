package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/perseworks/sentinella2/pkg/knowledge"
)

// baseFinding returns a Finding with all fields populated for use in table tests.
func baseFinding() Finding {
	return Finding{
		RuleID:      "injection/sql",
		PatternRef:  "injection/sql",
		Severity:    knowledge.SeverityHigh,
		File:        "/project/src/db/query.go",
		Line:        42,
		Column:      10,
		Message:     "SQL query built from user input",
		MatchedText: `db.Query("SELECT * FROM users WHERE id = " + userID)`,
		Context:     "handlers.go:42",
		FixHint:     "Use parameterised queries",
		Confidence:  0,
	}
}

func TestStableID_Deterministic(t *testing.T) {
	t.Parallel()

	f := baseFinding()
	rootDir := "/project"

	id1 := f.StableID(rootDir)
	id2 := f.StableID(rootDir)

	if id1 != id2 {
		t.Errorf("StableID not deterministic: %q vs %q", id1, id2)
	}
}

func TestStableID_LineIndependent(t *testing.T) {
	t.Parallel()

	f1 := baseFinding()
	f2 := baseFinding()
	f2.Line = f1.Line + 100

	rootDir := "/project"
	if id1, id2 := f1.StableID(rootDir), f2.StableID(rootDir); id1 != id2 {
		t.Errorf("StableID should not change when Line changes: %q vs %q", id1, id2)
	}
}

func TestStableID_ColumnIndependent(t *testing.T) {
	t.Parallel()

	f1 := baseFinding()
	f2 := baseFinding()
	f2.Column = f1.Column + 5

	rootDir := "/project"
	if id1, id2 := f1.StableID(rootDir), f2.StableID(rootDir); id1 != id2 {
		t.Errorf("StableID should not change when Column changes: %q vs %q", id1, id2)
	}
}

func TestStableID_DifferentFiles(t *testing.T) {
	t.Parallel()

	f1 := baseFinding()
	f2 := baseFinding()
	f2.File = "/project/src/api/handler.go"

	rootDir := "/project"
	if id1, id2 := f1.StableID(rootDir), f2.StableID(rootDir); id1 == id2 {
		t.Errorf("StableID should differ for different files, both got %q", id1)
	}
}

func TestStableID_DifferentPatterns(t *testing.T) {
	t.Parallel()

	f1 := baseFinding()
	f2 := baseFinding()
	f2.PatternRef = "injection/nosql"

	rootDir := "/project"
	if id1, id2 := f1.StableID(rootDir), f2.StableID(rootDir); id1 == id2 {
		t.Errorf("StableID should differ for different PatternRef, both got %q", id1)
	}
}

func TestStableID_Format(t *testing.T) {
	t.Parallel()

	f := baseFinding()
	id := f.StableID("/project")

	// Expected format: "{PatternRef}-{8 hex chars}"
	wantPrefix := f.PatternRef + "-"
	if len(id) < len(wantPrefix)+8 {
		t.Fatalf("StableID %q is too short (want at least %d chars)", id, len(wantPrefix)+8)
	}

	if id[:len(wantPrefix)] != wantPrefix {
		t.Errorf("StableID %q does not start with %q", id, wantPrefix)
	}

	hexPart := id[len(wantPrefix):]
	if len(hexPart) != 8 {
		t.Errorf("hex suffix of StableID %q has length %d, want 8", id, len(hexPart))
	}

	hexRe := regexp.MustCompile(`^[0-9a-f]{8}$`)
	if !hexRe.MatchString(hexPart) {
		t.Errorf("hex suffix %q is not 8 lowercase hex chars", hexPart)
	}
}

func TestStableID_EmptyRootDir(t *testing.T) {
	t.Parallel()

	f := baseFinding()
	// Empty rootDir should not panic; it should use the File path as-is.
	id := f.StableID("")
	if id == "" {
		t.Error("StableID with empty rootDir returned empty string")
	}
}

func TestNormalizeMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantRe  string // regex the output must match
		notWant string // substring that must NOT appear in output
	}{
		{
			name:    "HTTP GET path is replaced",
			input:   "Unsafe call: GET /api/v1/users",
			wantRe:  `<HTTP_METHOD_PATH>`,
			notWant: "/api/v1/users",
		},
		{
			name:    "HTTP POST path is replaced",
			input:   "Missing auth: POST /admin/reset",
			wantRe:  `<HTTP_METHOD_PATH>`,
			notWant: "/admin/reset",
		},
		{
			name:   "double-quoted string is replaced",
			input:  `SQL built from "user input"`,
			wantRe: `<STR>`,
		},
		{
			name:   "single-quoted string is replaced",
			input:  `value is 'secret'`,
			wantRe: `<STR>`,
		},
		{
			name:   "bare number is replaced",
			input:  "found 42 vulnerabilities",
			wantRe: `<NUM>`,
		},
		{
			name:    "plain message is unchanged",
			input:   "SQL query built from user input",
			wantRe:  "SQL query built from user input",
			notWant: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeMessage(tt.input)
			if tt.wantRe != "" {
				re := regexp.MustCompile(regexp.QuoteMeta(tt.wantRe))
				if !re.MatchString(got) {
					t.Errorf("normalizeMessage(%q) = %q; want it to contain %q", tt.input, got, tt.wantRe)
				}
			}
			if tt.notWant != "" && regexp.MustCompile(regexp.QuoteMeta(tt.notWant)).MatchString(got) {
				t.Errorf("normalizeMessage(%q) = %q; must not contain %q", tt.input, got, tt.notWant)
			}
		})
	}
}

func TestStableID_NormalisedMessageStable(t *testing.T) {
	t.Parallel()

	// Two findings with the same pattern but different specific values in the
	// message that normalisation should collapse to the same placeholder.
	f1 := baseFinding()
	f1.Message = `SQL built from "userID"`

	f2 := baseFinding()
	f2.Message = `SQL built from "orderID"`

	rootDir := "/project"
	id1 := f1.StableID(rootDir)
	id2 := f2.StableID(rootDir)

	if id1 != id2 {
		t.Errorf("StableID should be equal after message normalisation: %q vs %q", id1, id2)
	}
}

func TestFinding_ConfidenceDefaultsZero(t *testing.T) {
	t.Parallel()

	f := Finding{
		PatternRef: "auth/missing",
		File:       "main.go",
		Message:    "missing auth",
	}
	if f.Confidence != 0 {
		t.Errorf("Confidence default: got %v, want 0", f.Confidence)
	}
}

// TestStableID_Parallel exercises concurrent calls to verify no data races.
func TestStableID_Parallel(t *testing.T) {
	t.Parallel()

	f := baseFinding()
	const goroutines = 50

	results := make(chan string, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			results <- f.StableID("/project")
		}()
	}

	var first string
	for i := 0; i < goroutines; i++ {
		id := <-results
		if first == "" {
			first = id
		} else if id != first {
			t.Errorf("concurrent StableID: got %q and %q", first, id)
		}
	}
}

// TestStableID_FormatTable verifies the format property across several distinct
// PatternRef values to ensure slashes in the ref are preserved as-is.
func TestStableID_FormatTable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		patternRef string
		file       string
		message    string
	}{
		{"injection/sql", "/proj/main.go", "sql injection"},
		{"auth/idor", "/proj/handler.go", "IDOR found"},
		{"crypto/weak-hash", "/proj/util.go", "MD5 used"},
	}

	hexRe := regexp.MustCompile(`^[0-9a-f]{8}$`)

	for _, tt := range tests {
		t.Run(tt.patternRef, func(t *testing.T) {
			t.Parallel()
			f := Finding{PatternRef: tt.patternRef, File: tt.file, Message: tt.message}
			id := f.StableID("/proj")

			expected := fmt.Sprintf("%s-", tt.patternRef)
			if id[:len(expected)] != expected {
				t.Errorf("StableID %q does not start with %q", id, expected)
			}
			hex := id[len(expected):]
			if len(hex) != 8 || !hexRe.MatchString(hex) {
				t.Errorf("hex suffix %q is not 8 lowercase hex chars", hex)
			}
		})
	}
}

// minimalPattern returns a Pattern with a regex rule for the given language and
// pattern ID that matches the literal string "VULN_MARKER" in source content.
func minimalPattern(id, lang string) knowledge.Pattern {
	return knowledge.Pattern{
		ID:       id,
		Name:     id,
		Severity: knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 1,
			Rules: map[string]knowledge.RuleSet{
				lang: {Pattern: `VULN_MARKER`},
			},
		},
	}
}

// newTestScanner creates a RuleScanner wired with the supplied options.
func newTestScanner(opts ...Option) *RuleScanner {
	return New(opts...)
}

func TestMemorySkipsPattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mems      []knowledge.Memory
		patternID string
		want      bool
	}{
		{
			name: "scanner-scoped memory matching pattern skips it",
			mems: []knowledge.Memory{
				{Scope: knowledge.ScopeScanner, Scanner: "S7", Text: "not applicable"},
			},
			patternID: "S7",
			want:      true,
		},
		{
			name: "scanner-scoped memory for different pattern does not skip",
			mems: []knowledge.Memory{
				{Scope: knowledge.ScopeScanner, Scanner: "S8", Text: "not applicable"},
			},
			patternID: "S7",
			want:      false,
		},
		{
			name: "project-scoped memory does not skip patterns",
			mems: []knowledge.Memory{
				{Scope: knowledge.ScopeProject, Text: "we use TLS everywhere"},
			},
			patternID: "S7",
			want:      false,
		},
		{
			name: "pattern-scoped memory does not skip patterns",
			mems: []knowledge.Memory{
				{Scope: knowledge.ScopePattern, FileMatch: "**/*.go", Text: "reviewed"},
			},
			patternID: "S7",
			want:      false,
		},
		{
			name:      "empty memories never skip",
			mems:      nil,
			patternID: "S7",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := memorySkipsPattern(tt.mems, tt.patternID)
			if got != tt.want {
				t.Errorf("memorySkipsPattern(..., %q) = %v, want %v", tt.patternID, got, tt.want)
			}
		})
	}
}

func TestScanFile_MemorySkipsPattern(t *testing.T) {
	t.Parallel()

	const patternID = "S7"
	const lang = "go"
	const content = "func foo() { VULN_MARKER }" // triggers pattern

	// Build a MemoryStore in a temp file declaring S7 not applicable.
	tmp := t.TempDir()
	memPath := filepath.Join(tmp, "memories.yaml")
	ms, err := knowledge.OpenMemoryStore(memPath)
	if err != nil {
		t.Fatalf("OpenMemoryStore: %v", err)
	}
	if err := ms.Add(knowledge.Memory{
		Scope:   knowledge.ScopeScanner,
		Scanner: patternID,
		Text:    "S7 not applicable in this project",
	}); err != nil {
		t.Fatalf("ms.Add: %v", err)
	}

	s := newTestScanner(WithMemories(ms))
	patterns := []knowledge.Pattern{minimalPattern(patternID, lang)}

	findings := s.scanFile(context.Background(), "main.go", lang, []byte(content), patterns)
	if len(findings) != 0 {
		t.Errorf("expected no findings when memory skips pattern, got %d", len(findings))
	}
}

func TestScanFile_CalibrationSetsConfidence(t *testing.T) {
	t.Parallel()

	const patternID = "auth/missing"
	const lang = "go"
	const content = "func foo() { VULN_MARKER }"

	tmp := t.TempDir()
	calPath := filepath.Join(tmp, "calibration.json")
	cs, err := knowledge.OpenCalibrationStore(calPath, nil)
	if err != nil {
		t.Fatalf("OpenCalibrationStore: %v", err)
	}

	// Record enough confirmed verdicts to surpass the min-sample threshold (5).
	for i := 0; i < 5; i++ {
		cs.RecordVerdict(patternID, "*.go", knowledge.VerdictConfirmed)
	}

	// alpha=5, beta=1 → confidence = 5/6 ≈ 0.833
	wantConf := cs.ConfidenceFor(patternID, "main.go")
	if wantConf <= 0.5 {
		t.Fatalf("precondition: calibration confidence should be > 0.5, got %v", wantConf)
	}

	s := newTestScanner(WithCalibration(cs))
	patterns := []knowledge.Pattern{minimalPattern(patternID, lang)}

	findings := s.scanFile(context.Background(), "main.go", lang, []byte(content), patterns)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	got := findings[0].Confidence
	// stable pattern weight = 1.0, so conf = wantConf * 1.0
	if got != wantConf {
		t.Errorf("Confidence = %v, want %v", got, wantConf)
	}
}

func TestScanFile_DefaultConfidence(t *testing.T) {
	t.Parallel()

	const lang = "go"
	const content = "func foo() { VULN_MARKER }"

	// No calibration store provided — should default to 0.5 * lifecycle weight.
	s := newTestScanner() // no WithCalibration
	patterns := []knowledge.Pattern{minimalPattern("auth/missing", lang)}

	findings := s.scanFile(context.Background(), "main.go", lang, []byte(content), patterns)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Cold start default: 0.5 * EffectiveConfidenceWeight (stable=1.0) = 0.5.
	const wantConf = 0.5
	if findings[0].Confidence != wantConf {
		t.Errorf("Confidence = %v, want %v (cold start default)", findings[0].Confidence, wantConf)
	}
}

// openCalibrationStoreForTest creates a CalibrationStore backed by a temp file.
func openCalibrationStoreForTest(t *testing.T) *knowledge.CalibrationStore {
	t.Helper()
	cs, err := knowledge.OpenCalibrationStore(
		filepath.Join(t.TempDir(), "calibration.json"),
		nil,
	)
	if err != nil {
		t.Fatalf("OpenCalibrationStore: %v", err)
	}
	return cs
}

// patternWithNeg returns a Pattern with positive and negative regex rules.
func patternWithNeg(id, lang, pos, neg string) knowledge.Pattern {
	return knowledge.Pattern{
		ID:       id,
		Name:     id,
		Severity: knowledge.SeverityHigh,
		Detection: knowledge.Detection{
			Tier: 1,
			Rules: map[string]knowledge.RuleSet{
				lang: {Pattern: pos, NegativePattern: neg},
			},
		},
	}
}

func TestNewRules_MissingRetryAfter(t *testing.T) {
	t.Parallel()

	pat := patternWithNeg(
		"resilience/missing-retry-after", "go",
		`StatusTooManyRequests|status\(429\)|WriteHeader\(429\)|AbortWithStatus.*429`,
		`Retry-After|retry.?after|RetryAfter|Header\(\)\.Set\(.*[Rr]etry`,
	)
	pat.Severity = knowledge.SeverityMedium

	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "vulnerable: 429 without Retry-After",
			content: `func rateLimitHandler(c *gin.Context) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			}`,
			want: 1,
		},
		{
			name: "mitigated: 429 with Retry-After header",
			content: `func rateLimitHandler(c *gin.Context) {
				c.Header("Retry-After", "60")
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
			}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newTestScanner()
			findings := s.scanFile(context.Background(), "middleware.go", "go", []byte(tt.content), []knowledge.Pattern{pat})
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestNewRules_RateLimitBlocksRefresh(t *testing.T) {
	t.Parallel()

	pat := patternWithNeg(
		"resilience/rate-limit-blocks-refresh", "go",
		`r\.Use\(.*[Rr]ate[Ll]imit|middleware\.[Rr]ate[Ll]imit|limiter\.Handler|tollbooth\.LimitHandler`,
		`refresh.*[Ee]xclude|[Ee]xclude.*refresh|SkipPaths.*refresh|auth/refresh|token/refresh`,
	)

	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "vulnerable: global rate limit without refresh exclusion",
			content: `func setupRouter(r *gin.Engine) {
				r.Use(middleware.RateLimit(60))
				r.POST("/auth/login", handleLogin)
				r.POST("/users", handleUsers)
			}`,
			want: 1,
		},
		{
			name: "mitigated: rate limit excludes refresh",
			content: `func setupRouter(r *gin.Engine) {
				r.Use(middleware.RateLimit(60, ratelimit.ExcludePaths("/auth/refresh")))
			}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newTestScanner()
			findings := s.scanFile(context.Background(), "router.go", "go", []byte(tt.content), []knowledge.Pattern{pat})
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestNewRules_BypassAuthClient(t *testing.T) {
	t.Parallel()

	pat := patternWithNeg(
		"auth-flow/bypass-auth-client", "go",
		`http\.Get\(|http\.Post\(|http\.NewRequest\(|http\.DefaultClient|&http\.Client\{\}`,
		`authClient\.|apiClient\.|AuthenticatedClient|NewAuthClient|auth\.Client|RoundTripper`,
	)

	tests := []struct {
		name    string
		content string
		want    int
	}{
		{
			name: "vulnerable: raw http.Get bypasses auth client",
			content: `func getUsers() (*http.Response, error) {
				return http.Get("http://internal-api/users")
			}`,
			want: 1,
		},
		{
			name: "mitigated: uses auth client",
			content: `func getUsers(authClient *auth.Client) (*http.Response, error) {
				return authClient.Get(ctx, "/users")
			}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newTestScanner()
			findings := s.scanFile(context.Background(), "service.go", "go", []byte(tt.content), []knowledge.Pattern{pat})
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

