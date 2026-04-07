# sentinella2

Security audit engine with embedded knowledge base. Born from 93 real-world vulnerabilities and FreeBSD CVE-2026-4747.

**Not another SAST scanner.** sentinella2 embeds battle-tested security knowledge from a full-platform audit into a single binary -- usable standalone, with any LLM, or integrated into any tool.

## Features

- **Zero-config scanning**: `sentinella2 scan ./project` finds hardcoded secrets, misconfigurations, and common vulnerabilities with no setup
- **Model-agnostic deep audit**: Connect any LLM (Claude, GPT, GLM, Llama, Ollama) for semantic analysis that catches vulnerabilities SAST tools miss
- **6-layer defense assessment**: Evaluate defense-in-depth posture (Ingress -> Isolation -> Hardening -> Access Control -> Data Protection -> Tamper Detection)
- **Real-world knowledge base**: 7 vulnerability patterns derived from 93 production vulnerabilities + 21 FreeBSD Security Advisories
- **Pluggable**: CLI + MCP Server + Go Library + CI/CD integration

## Quick Start

### Install

```bash
# From source
go install github.com/perseworks/sentinella2/cmd/sentinella2@latest

# Or download binary
curl -sSL https://github.com/perseworks/sentinella2/releases/latest/download/sentinella2-$(uname -s)-$(uname -m) -o sentinella2
chmod +x sentinella2
```

### Scan (No LLM required)

```bash
sentinella2 scan ./my-project
```

### Deep Audit (Any LLM)

```bash
# Claude
sentinella2 audit ./my-project --provider anthropic --model claude-sonnet-4-6 --api-key $ANTHROPIC_API_KEY

# GPT
sentinella2 audit ./my-project --provider openai-compatible --base-url https://api.openai.com/v1 --model gpt-4o --api-key $OPENAI_API_KEY

# Local Ollama
sentinella2 audit ./my-project --provider openai-compatible --base-url http://localhost:11434/v1 --model llama3

# ZhipuAI GLM
sentinella2 audit ./my-project --provider openai-compatible --base-url https://open.bigmodel.cn/api/paas/v4 --model glm-4 --api-key $ZHIPU_API_KEY
```

### Defense Layers

```bash
sentinella2 check-layers ./my-project
```

## Integration

### MCP Server (Claude Code, Cursor, VS Code)

```json
{
  "mcpServers": {
    "sentinella2": {
      "command": "sentinella2-mcp"
    }
  }
}
```

### Go Library

```go
import (
    "github.com/perseworks/sentinella2/pkg/scan"
    "github.com/perseworks/sentinella2/pkg/knowledge"
)

kb, _ := knowledge.LoadFromDir("./knowledge")
scanner := scan.New(scan.WithKnowledge(kb))
result, _ := scanner.Scan(ctx, "./my-project")
```

### CI/CD

See [examples/github-action.yaml](examples/github-action.yaml) and [examples/gitlab-ci.yaml](examples/gitlab-ci.yaml).

### Git Hooks

```bash
sentinella2 hooks install
```

## Knowledge Base

### 7 Vulnerability Patterns

| Pattern | Rules | Tier | OWASP |
|---------|-------|------|-------|
| Input Boundary | 5 | 1-2 | A03 |
| Auth Flow | 6 | 2-3 | A01, A02, A07 |
| Isolation | 4 | 1 | A05 |
| Resilience | 4 | 2-3 | A04, A07, A09 |
| Injection | 3 | 1-2 | A03, A10 |
| Trust Chain | 3 | 2-3 | A07, A08, A10 |
| Info Leakage | 4 | 1 | A05, A09 |

### 3-Tier Detection

- **Tier 1** (~32% coverage): Deterministic regex matching. Zero false positives. No LLM needed.
- **Tier 2** (~38% coverage): Structural analysis with context. Requires code understanding.
- **Tier 3** (~30% coverage): Semantic analysis. Requires LLM reasoning.

### 6-Layer Defense-in-Depth

Inspired by FreeBSD security architecture:

| Layer | Check | FreeBSD Analog |
|-------|-------|---------------|
| 1. Ingress | TLS, WAF, HSTS | pf firewall |
| 2. Isolation | Namespace, NetworkPolicy | jail + vnet |
| 3. Hardening | Non-root, read-only FS, seccomp | capsicum |
| 4. Access Control | RBAC, auth middleware | MAC framework |
| 5. Data Protection | Encrypted DB, log masking | GELI |
| 6. Tamper Detection | Audit trail, config fingerprint | Immutable logs |

## Why sentinella2?

Traditional SAST tools (Semgrep, CodeQL) find ~32% of real vulnerabilities. The most dangerous ones -- payment signature bypass, OTP backdoors, IDOR, fail-open middleware -- require understanding **what code is supposed to do**, not just what it looks like.

sentinella2 bridges this gap by combining deterministic rules with LLM-powered semantic analysis, guided by patterns from 93 real vulnerabilities that were all found and fixed in production.

## Configuration

Create `.sentinella2.yaml` in your project root:

```yaml
scan:
  exclude: ["vendor/**", "node_modules/**"]
  disable_rules: ["info-leakage/console-leak"]

audit:
  provider: "openai-compatible"
  base_url: "http://localhost:11434/v1"
  model: "llama3"

defense_layers:
  disable: ["tamper-detection"]
```

## License

MIT
