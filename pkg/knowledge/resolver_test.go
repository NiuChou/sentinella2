package knowledge

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

// minimalPatternYAML returns valid YAML for a single pattern file.
func minimalPatternYAML(id, severity string) string {
	return `schema_version: "1.0"
kind: patterns
category: test
patterns:
  - id: "` + id + `"
    name: "Test Pattern"
    description: "A test pattern"
    severity: "` + severity + `"
    detection:
      abstract: "detect something"
      tier: 1
    fix:
      abstract: "fix it"
`
}

// buildTestFS creates an fstest.MapFS with the given patterns directory content.
func buildTestFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for path, content := range files {
		m[path] = &fstest.MapFile{Data: []byte(content)}
	}
	return m
}

func TestResolverSingleBuiltin(t *testing.T) {
	t.Parallel()

	testFS := buildTestFS(map[string]string{
		"kb/patterns/test.yaml": minimalPatternYAML("test/p1", "HIGH"),
	})

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: true},
	}

	resolver := NewResolver(sources, MergeOverlay)
	kb, err := resolver.Resolve(testFS, "kb")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if kb.PatternCount() != 1 {
		t.Errorf("expected 1 pattern, got %d", kb.PatternCount())
	}

	p, ok := kb.PatternByID("test/p1")
	if !ok {
		t.Fatal("pattern test/p1 not found")
	}
	if p.Severity != SeverityHigh {
		t.Errorf("severity = %s, want HIGH", p.Severity)
	}
}

func TestResolverOverlayStrategy(t *testing.T) {
	t.Parallel()

	baseFS := buildTestFS(map[string]string{
		"kb/patterns/base.yaml": minimalPatternYAML("shared/p1", "HIGH"),
	})

	overlayDir := t.TempDir()
	writePatternFile(t, overlayDir, "overlay.yaml", "shared/p1", "CRITICAL")

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: true},
		{Type: SourceLocal, Path: overlayDir, Priority: 10, Enabled: true},
	}

	resolver := NewResolver(sources, MergeOverlay)
	kb, err := resolver.Resolve(baseFS, "kb")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Overlay should replace the base pattern.
	if kb.PatternCount() != 1 {
		t.Errorf("expected 1 pattern (overlay replaces), got %d", kb.PatternCount())
	}
	p, ok := kb.PatternByID("shared/p1")
	if !ok {
		t.Fatal("pattern shared/p1 not found")
	}
	if p.Severity != SeverityCritical {
		t.Errorf("severity = %s, want CRITICAL (overlay should win)", p.Severity)
	}
}

func TestResolverStrictStrategy(t *testing.T) {
	t.Parallel()

	baseFS := buildTestFS(map[string]string{
		"kb/patterns/base.yaml": minimalPatternYAML("shared/p1", "HIGH"),
	})

	overlayDir := t.TempDir()
	writePatternFile(t, overlayDir, "overlay.yaml", "shared/p1", "CRITICAL")

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: true},
		{Type: SourceLocal, Path: overlayDir, Priority: 10, Enabled: true},
	}

	resolver := NewResolver(sources, MergeStrict)
	_, err := resolver.Resolve(baseFS, "kb")
	if err == nil {
		t.Fatal("expected error for conflicting IDs in strict mode")
	}
}

func TestResolverAdditiveStrategy(t *testing.T) {
	t.Parallel()

	baseFS := buildTestFS(map[string]string{
		"kb/patterns/base.yaml": minimalPatternYAML("shared/p1", "HIGH"),
	})

	overlayDir := t.TempDir()
	writePatternFile(t, overlayDir, "overlay.yaml", "shared/p1", "CRITICAL")

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: true},
		{Type: SourceLocal, Path: overlayDir, Priority: 10, Enabled: true},
	}

	resolver := NewResolver(sources, MergeAdditive)
	kb, err := resolver.Resolve(baseFS, "kb")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Additive keeps both: original + suffixed overlay.
	if kb.PatternCount() != 2 {
		t.Errorf("expected 2 patterns (additive), got %d", kb.PatternCount())
	}

	_, okOrig := kb.PatternByID("shared/p1")
	_, okOverlay := kb.PatternByID("shared/p1:overlay")
	if !okOrig {
		t.Error("original pattern shared/p1 not found")
	}
	if !okOverlay {
		t.Error("overlay pattern shared/p1:overlay not found")
	}
}

func TestResolverMissingDirectory(t *testing.T) {
	t.Parallel()

	baseFS := buildTestFS(map[string]string{
		"kb/patterns/base.yaml": minimalPatternYAML("test/p1", "HIGH"),
	})

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: true},
		{Type: SourceLocal, Path: "/nonexistent/path/that/does/not/exist", Priority: 10, Enabled: true},
	}

	resolver := NewResolver(sources, MergeOverlay)
	kb, err := resolver.Resolve(baseFS, "kb")
	if err != nil {
		t.Fatalf("expected no error for missing dir, got: %v", err)
	}

	// Missing dir contributes an empty KB; base should still be present.
	if kb.PatternCount() != 1 {
		t.Errorf("expected 1 pattern, got %d", kb.PatternCount())
	}
}

func TestResolverNoEnabledSources(t *testing.T) {
	t.Parallel()

	sources := []KnowledgeSource{
		{Type: SourceBuiltin, Path: "", Priority: 0, Enabled: false},
	}

	resolver := NewResolver(sources, MergeOverlay)
	_, err := resolver.Resolve(fstest.MapFS{}, "kb")
	if err == nil {
		t.Fatal("expected error for no enabled sources")
	}
}

func TestResolverPriorityOrdering(t *testing.T) {
	t.Parallel()

	// Lower priority loads first; higher priority overlays on top.
	lowFS := buildTestFS(map[string]string{
		"kb/patterns/low.yaml": minimalPatternYAML("order/p1", "LOW"),
	})

	highDir := t.TempDir()
	writePatternFile(t, highDir, "high.yaml", "order/p1", "CRITICAL")

	sources := []KnowledgeSource{
		{Type: SourceLocal, Path: highDir, Priority: 100, Enabled: true},
		{Type: SourceBuiltin, Path: "", Priority: 1, Enabled: true},
	}

	resolver := NewResolver(sources, MergeOverlay)
	kb, err := resolver.Resolve(lowFS, "kb")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	p, ok := kb.PatternByID("order/p1")
	if !ok {
		t.Fatal("pattern not found")
	}
	if p.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL (higher priority wins), got %s", p.Severity)
	}
}

// writePatternFile writes a minimal pattern YAML file under dir/patterns/.
func writePatternFile(t *testing.T, dir, filename, id, severity string) {
	t.Helper()

	patternsDir := dir + "/patterns"
	if err := fs.ValidPath(patternsDir); err == nil {
		// Create the patterns subdirectory.
	}

	if err := mkdirAll(patternsDir); err != nil {
		t.Fatalf("mkdir patterns: %v", err)
	}

	content := minimalPatternYAML(id, severity)
	if err := writeFile(patternsDir+"/"+filename, []byte(content)); err != nil {
		t.Fatalf("write pattern file: %v", err)
	}
}

// mkdirAll wraps os.MkdirAll for test helpers.
func mkdirAll(path string) error {
	return osWriteHelper("mkdir", path, nil)
}

// writeFile wraps os.WriteFile for test helpers.
func writeFile(path string, data []byte) error {
	return osWriteHelper("write", path, data)
}

// osWriteHelper is a small helper to avoid importing os in multiple places.
func osWriteHelper(op, path string, data []byte) error {
	switch op {
	case "mkdir":
		return osMkdirAll(path)
	case "write":
		return osWriteFile(path, data)
	default:
		return nil
	}
}
