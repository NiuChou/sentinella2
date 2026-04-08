package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempFile creates a file with the given content in dir, returning the path.
func writeTempFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatalf("create parent dir for %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", name, err)
	}
}

func TestDetectStack_NestJS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTempFile(t, dir, "nest-cli.json", `{"$schema":"..."}`)

	got := DetectStack(dir)

	if got.ID != "nestjs" {
		t.Errorf("ID: got %q, want %q", got.ID, "nestjs")
	}
	if got.Confidence <= 0 {
		t.Errorf("Confidence: got %v, want > 0", got.Confidence)
	}
	if len(got.Frameworks) == 0 || got.Frameworks[0] != "nestjs" {
		t.Errorf("Frameworks: got %v, want [nestjs]", got.Frameworks)
	}
}

func TestDetectStack_FastAPI(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTempFile(t, dir, "requirements.txt", "fastapi==0.100.0\nuvicorn\n")

	got := DetectStack(dir)

	if got.ID != "fastapi" {
		t.Errorf("ID: got %q, want %q", got.ID, "fastapi")
	}
	if got.Confidence <= 0 {
		t.Errorf("Confidence: got %v, want > 0", got.Confidence)
	}
}

func TestDetectStack_Gin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTempFile(t, dir, "go.mod", "module example.com/app\n\nrequire github.com/gin-gonic/gin v1.9.0\n")

	got := DetectStack(dir)

	if got.ID != "gin" {
		t.Errorf("ID: got %q, want %q", got.ID, "gin")
	}
}

func TestDetectStack_NoMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	got := DetectStack(dir)

	if got.ID != "" {
		t.Errorf("ID: got %q, want empty string (no match)", got.ID)
	}
	if got.Confidence != 0 {
		t.Errorf("Confidence: got %v, want 0", got.Confidence)
	}
}

func TestDetectStack_ContentMatch_FileExistsNoSubstring(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// requirements.txt exists but does NOT contain "fastapi"
	writeTempFile(t, dir, "requirements.txt", "requests==2.28.0\nflask==3.0.0\n")

	got := DetectStack(dir)

	if got.ID == "fastapi" {
		t.Errorf("ID: got %q, want not fastapi (file exists but no substr match)", got.ID)
	}
}

func TestDetectStack_BestMatch(t *testing.T) {
	t.Parallel()

	// Create a dir that matches both nestjs (1 of 2 files) and gin (1 of 1 file).
	// gin has conf 1.0 (1/1), nestjs has conf 0.5 (1/2), so gin should win.
	dir := t.TempDir()
	writeTempFile(t, dir, "nest-cli.json", `{}`)
	writeTempFile(t, dir, "go.mod", "module example.com/app\n\nrequire github.com/gin-gonic/gin v1.9.0\n")

	got := DetectStack(dir)

	if got.ID != "gin" {
		t.Errorf("ID: got %q, want %q (gin has higher confidence)", got.ID, "gin")
	}
	if got.Confidence != 1.0 {
		t.Errorf("Confidence: got %v, want 1.0", got.Confidence)
	}
}

func TestCheckFileSpec_ExistOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTempFile(t, dir, "manage.py", "# django manage.py\n")

	tests := []struct {
		name string
		spec string
		want bool
	}{
		{name: "exists", spec: "manage.py", want: true},
		{name: "not_exists", spec: "missing.py", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkFileSpec(dir, tc.spec)
			if got != tc.want {
				t.Errorf("checkFileSpec(%q, %q) = %v, want %v", dir, tc.spec, got, tc.want)
			}
		})
	}
}

func TestCheckFileSpec_ContentCheck(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTempFile(t, dir, "requirements.txt", "fastapi==0.100.0\nuvicorn\n")

	tests := []struct {
		name string
		spec string
		want bool
	}{
		{name: "matches_substr", spec: "requirements.txt:fastapi", want: true},
		{name: "wrong_substr", spec: "requirements.txt:django", want: false},
		{name: "missing_file", spec: "absent.txt:fastapi", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkFileSpec(dir, tc.spec)
			if got != tc.want {
				t.Errorf("checkFileSpec(%q, %q) = %v, want %v", dir, tc.spec, got, tc.want)
			}
		})
	}
}
