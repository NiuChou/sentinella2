package knowledge

import (
	"os"
	"path/filepath"
	"strings"
)

// TechStack describes the detected technology stack of a project.
type TechStack struct {
	ID         string   // e.g. "nestjs", "fastapi", "gin"
	Name       string   // human-readable, e.g. "NestJS"
	Frameworks []string // detected framework identifiers
	Languages  []string // primary languages
	Confidence float64  // 0.0-1.0 detection confidence
}

// stackSignature defines how to detect a tech stack from file presence.
type stackSignature struct {
	ID        string
	Name      string
	Languages []string
	// Files lists files whose existence signals this stack.
	// Format: "filename" or "filename:content_substr" (check file contains substring).
	Files []string
	// MinMatches is how many files need to match (1 = any match).
	MinMatches int
}

var knownStacks = []stackSignature{
	{
		ID: "nestjs", Name: "NestJS", Languages: []string{"typescript"},
		Files:      []string{"nest-cli.json", "package.json:@nestjs/core"},
		MinMatches: 1,
	},
	{
		ID: "nextjs", Name: "Next.js", Languages: []string{"typescript", "javascript"},
		Files:      []string{"next.config.js", "next.config.mjs", "next.config.ts", "package.json:next"},
		MinMatches: 1,
	},
	{
		ID: "fastapi", Name: "FastAPI", Languages: []string{"python"},
		Files:      []string{"requirements.txt:fastapi", "pyproject.toml:fastapi", "Pipfile:fastapi"},
		MinMatches: 1,
	},
	{
		ID: "django", Name: "Django", Languages: []string{"python"},
		Files:      []string{"manage.py", "requirements.txt:django", "pyproject.toml:django"},
		MinMatches: 1,
	},
	{
		ID: "rails", Name: "Ruby on Rails", Languages: []string{"ruby"},
		Files:      []string{"Gemfile:rails", "config/routes.rb"},
		MinMatches: 1,
	},
	{
		ID: "gin", Name: "Gin (Go)", Languages: []string{"go"},
		Files:      []string{"go.mod:gin-gonic/gin"},
		MinMatches: 1,
	},
	{
		ID: "express", Name: "Express.js", Languages: []string{"javascript"},
		Files:      []string{"package.json:express"},
		MinMatches: 1,
	},
	{
		ID: "spring", Name: "Spring Boot", Languages: []string{"java", "kotlin"},
		Files:      []string{"pom.xml:spring-boot", "build.gradle:spring-boot"},
		MinMatches: 1,
	},
	{
		ID: "laravel", Name: "Laravel", Languages: []string{"php"},
		Files:      []string{"artisan", "composer.json:laravel/framework"},
		MinMatches: 1,
	},
	{
		ID: "flask", Name: "Flask", Languages: []string{"python"},
		Files:      []string{"requirements.txt:flask", "pyproject.toml:flask"},
		MinMatches: 1,
	},
	{
		ID: "svelte", Name: "SvelteKit", Languages: []string{"typescript", "javascript"},
		Files:      []string{"svelte.config.js", "package.json:@sveltejs/kit"},
		MinMatches: 1,
	},
	{
		ID: "nuxt", Name: "Nuxt", Languages: []string{"typescript", "javascript"},
		Files:      []string{"nuxt.config.ts", "nuxt.config.js", "package.json:nuxt"},
		MinMatches: 1,
	},
}

// DetectStack analyzes a project directory to identify its tech stack.
// Uses file existence heuristics only — no code parsing needed.
// Returns a zero TechStack if no stack is detected.
func DetectStack(targetDir string) TechStack {
	var best TechStack

	for _, sig := range knownStacks {
		matches := 0
		for _, fileSpec := range sig.Files {
			if checkFileSpec(targetDir, fileSpec) {
				matches++
			}
		}

		if matches >= sig.MinMatches {
			conf := float64(matches) / float64(len(sig.Files))
			if conf > best.Confidence {
				best = TechStack{
					ID:         sig.ID,
					Name:       sig.Name,
					Frameworks: []string{sig.ID},
					Languages:  sig.Languages,
					Confidence: conf,
				}
			}
		}
	}

	return best
}

// checkFileSpec checks if a file spec matches in the target directory.
// Format: "filename" (file exists) or "filename:substr" (file exists AND contains substr).
func checkFileSpec(targetDir, spec string) bool {
	parts := strings.SplitN(spec, ":", 2)
	filePath := filepath.Join(targetDir, parts[0])

	if len(parts) == 1 {
		// Just check existence.
		_, err := os.Stat(filePath)
		return err == nil
	}

	// Check existence + content substring.
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), parts[1])
}
