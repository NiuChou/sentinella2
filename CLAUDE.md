# sentinella2

Security audit knowledge base + engine. Born from perseworks 93-vulnerability audit and FreeBSD CVE-2026-4747 analysis.

## Project Structure

- `knowledge/` - YAML knowledge base (embedded into binary via Go embed)
  - `schema/` - YAML schema definitions
  - `patterns/` - 7 vulnerability pattern files
  - `defense-layers/` - 6-layer defense-in-depth definitions
  - `mappings/` - FreeBSD-SA and OWASP Top 10 mappings
  - `cases/` - 93 real-world vulnerability cases
  - `prompts/` - LLM audit prompt templates (model-agnostic)
- `cmd/sentinella2/` - CLI entry point
- `pkg/` - Public Go API (importable as library)
  - `scan/` - Core scan engine
  - `knowledge/` - Knowledge base loader
  - `report/` - Output formatters (text/json/markdown)
  - `provider/` - LLM provider abstraction (Anthropic/OpenAI/Ollama/any)
- `internal/` - Private implementation
  - `matcher/` - Regex/glob/YAML path matchers
  - `config/` - Project configuration

## Design Constraints

1. **Model-agnostic**: Works with any LLM (Claude/GPT/GLM/Llama/Ollama)
2. **Tool-agnostic**: No dependency on any specific IDE or AI tool
3. **Out-of-the-box**: `sentinella2 scan` works with zero configuration (Tier 1)
4. **Pluggable**: CLI + MCP Server + Go Library + CI integration

## Conventions

- Knowledge base: YAML format, embedded via `//go:embed`
- Immutable data structures throughout
- Error handling: explicit, no silent swallowing
- Files: 200-400 lines typical, 800 max
- Tests: TDD, 80%+ coverage target
