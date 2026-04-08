# sentinella2

Security audit engine with adaptive knowledge base. Born from 93 real-world vulnerabilities and FreeBSD CVE-2026-4747.

**Not another SAST scanner.** sentinella2 combines deterministic rules with Bayesian confidence calibration and LLM-powered semantic analysis. It learns from your feedback -- the more you use it, the more accurate it gets.

---

## [English](#english) | [中文](#中文)

---

## Project Structure / 工程结构

```
sentinella2/
├── cmd/
│   ├── sentinella2/                  # CLI entry point / CLI 入口
│   │   ├── main.go                   #   command dispatcher / 命令分发
│   │   ├── commands.go               #   scan, audit, check-layers / 核心命令实现
│   │   ├── kb.go                     #   kb subcommands / 知识库管理命令
│   │   ├── kb_feedback.go            #   feedback mark/stats / 反馈标注命令
│   │   ├── triage.go                 #   interactive labeling / 交互式标注
│   │   ├── learn.go                  #   pattern mining CLI / 模式挖掘命令
│   │   └── memory.go                 #   context memory CLI / 上下文记忆命令
│   └── sentinella2-mcp/              # MCP Server / MCP 服务器
│       ├── main.go
│       ├── server.go
│       ├── tools.go
│       └── definitions.go
│
├── pkg/                              # Public Go API (importable) / 公共 Go API
│   ├── scan/                         #   Core scan engine / 核心扫描引擎
│   │   ├── scanner.go                #     Scanner interface, Finding, Options
│   │   ├── rule_scanner.go           #     Tier 1 regex scanning + Memory/Calibration integration
│   │   ├── defense_scanner.go        #     6-layer defense assessment
│   │   ├── grading.go                #     Confidence grading (Confirmed/Likely/Suspect)
│   │   ├── correlation.go            #     Cross-scanner correlation (boost/penalty)
│   │   └── triage.go                 #     Guided labeling priority engine
│   │
│   ├── knowledge/                    #   Knowledge base + learning / 知识库 + 学习系统
│   │   ├── types.go                  #     Pattern, Case, DefenseLayer, Severity, Lifecycle
│   │   ├── knowledge.go              #     KnowledgeBase with indexes
│   │   ├── loader.go                 #     LoadFromFS / LoadFromDir
│   │   ├── resolver.go               #     Multi-source KB merging
│   │   ├── feedback.go               #     FeedbackStore (append-only verdicts)
│   │   ├── calibration.go            #     Bayesian CalibrationStore (Beta distribution)
│   │   ├── state.go                  #     FindingState persistence (cross-run tracking)
│   │   ├── memory.go                 #     Context Memory (3-level scope)
│   │   ├── lifecycle.go              #     Rule maturity engine (experimental → stable)
│   │   ├── miner.go                  #     FP pattern clustering + suggestions
│   │   ├── stackdetect.go            #     Tech stack detection (12 frameworks)
│   │   ├── tuner.go                  #     Feedback-driven pattern adjustment
│   │   ├── synthesizer.go            #     LLM-powered pattern generation
│   │   ├── feed.go                   #     Feed synchronization (NVD, GHSA)
│   │   ├── updater.go                #     Knowledge base updates
│   │   ├── registry.go               #     KB registry
│   │   └── prompts.go                #     LLM prompt templates
│   │
│   ├── provider/                     #   LLM provider abstraction / LLM 提供者抽象
│   │   ├── provider.go               #     Provider interface + Config
│   │   ├── openai.go                 #     OpenAI-compatible (Claude/GPT/GLM/Ollama)
│   │   └── noop.go                   #     No-op for scan-only mode
│   │
│   └── report/                       #   Output formatters / 输出格式化
│       ├── reporter.go               #     Reporter interface
│       ├── text.go                   #     Human-readable + confidence grading
│       ├── json.go                   #     Machine-parseable + confidence/grade fields
│       └── markdown.go               #     Documentation format + grade grouping
│
���── internal/                         # Private implementation / 内部实现
│   ├���─ config/
│   │   └── config.go                 #   .sentinella2.yaml loader + defaults
│   └── matcher/
│       ├── regex.go                  #   Thread-safe compiled regex cache
│       └── glob.go                   #   Glob matching with **/ support
│
├── knowledge/                        # Embedded YAML KB (go:embed) / 嵌入式知识库
│   ├── schema/                       #   YAML schema definitions
│   ├── patterns/                     #   7 vulnerability pattern files (29 rules)
│   ├── defense-layers/               #   6-layer defense-in-depth model
│   ├── mappings/                     #   FreeBSD-SA + OWASP Top 10 mappings
│   ├── cases/                        #   93 real-world vulnerability cases
│   ├── prompts/                      #   LLM audit prompt templates
│   └── priors/                       #   Built-in Bayesian priors from audit data
│
├── examples/                         # Integration examples / 集成示例
│   ├── github-action.yaml
│   ├── gitlab-ci.yaml
│   ├── sentinella2.yaml              #   Example config
│   ├── claude-code-hook.json
│   ├── cursor-mcp.json
│   └── vscode-mcp.json
│
├── hooks/                            # Git hooks / Git 钩子
├── embedded.go                       # go:embed declaration
├── go.mod                            # Single dep: gopkg.in/yaml.v3
└── .sentinella2/                     # Per-project learning data (gitignored)
    ├── state.json                    #   Finding lifecycle states
    ├── calibration.json              #   Bayesian β(α,β) buckets
    ├── memories.yaml                 #   User-declared context
    └── feedback/                     #   Monthly verdict YAML files
```

---

<a id="english"></a>

# English

## Features

- **Zero-config scanning**: `sentinella2 scan ./project` finds hardcoded secrets, misconfigurations, and common vulnerabilities with no setup
- **Adaptive learning**: Bayesian confidence calibration learns from your feedback -- 50 labels can reduce noise from 6,000 findings to 135 real issues
- **Context Memory**: Declare project context ("auth is handled at API Gateway") and the scanner skips irrelevant findings
- **Model-agnostic deep audit**: Connect any LLM (Claude, GPT, GLM, Llama, Ollama) for semantic analysis that catches vulnerabilities SAST tools miss
- **6-layer defense assessment**: Evaluate defense-in-depth posture inspired by FreeBSD security architecture
- **Cross-project knowledge transfer**: Share calibration data across projects with the same tech stack
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

## Adaptive Learning System

sentinella2 goes beyond static rules. It learns from your feedback through a 5-component adaptive pipeline:

### The Learning Loop

```
sentinella2 scan ./src             # 1. Scan: 6,080 findings (cold start)
sentinella2 memory add "auth at GW" # 2. Context: declare project facts
sentinella2 triage --batch 50      # 3. Label: guided labeling picks highest-value findings
sentinella2 scan ./src             # 4. Rescan: 135 findings (calibrated)
sentinella2 learn                  # 5. Learn: discover patterns, suggest rules
```

### Components

| Component | What it does | Storage |
|-----------|-------------|---------|
| **Finding Identity** | Stable IDs that survive code movement (line-number independent) | `.sentinella2/state.json` |
| **Context Memory** | User-declared project facts that skip irrelevant findings | `.sentinella2/memories.yaml` |
| **Bayesian Calibration** | Per-(pattern, file-type) Beta distribution from feedback | `.sentinella2/calibration.json` |
| **Confidence Grading** | Findings graded as Confirmed (>70%) / Likely (30-70%) / Suspect (<30%) | in scan output |
| **Pattern Miner** | Clusters false positives and suggests rules automatically | via `learn` command |
| **Rule Lifecycle** | Patterns mature: experimental -> testing -> stable -> deprecated | in pattern YAML |
| **Cross-Scanner Correlation** | 3+ independent patterns on same file -> confidence boost | post-scan adjustment |

### Tech Stack Prior Transfer

New project? No feedback yet? sentinella2 detects your tech stack and loads shared calibration from previous projects:

```bash
$ sentinella2 scan ./my-new-nestjs-project
Detected tech stack: NestJS (confidence: 95%)
Loading 12 calibration buckets from shared pool...

$ sentinella2 kb calibration export --stack nestjs  # Share back
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
scanner := scan.New(
    scan.WithKnowledge(kb),
    scan.WithCalibration(calStore),
    scan.WithMemories(memStore),
    scan.WithCorrelation(scan.DefaultCorrelationConfig()),
)
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

## CLI Reference

```
sentinella2 scan <path>               Tier 1 deterministic scan
sentinella2 audit <path>              Deep audit with LLM
sentinella2 check-layers <path>       Defense-in-depth assessment
sentinella2 triage <path> --batch N   Interactive labeling (guided in cold start)
sentinella2 learn                     Discover FP patterns, suggest rules
sentinella2 memory list|add|remove    Manage project context declarations
sentinella2 kb feedback mark <id>     Record finding verdicts
sentinella2 kb tune                   Apply feedback-driven tuning
sentinella2 kb calibration export     Export calibration for sharing
sentinella2 init                      Create default config
```

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

feedback:
  dir: ".sentinella2/feedback"
  auto_tune: true
  min_feedback: 5
  fp_threshold: 0.3

memory:
  file: ".sentinella2/memories.yaml"

rule_lifecycle:
  promote_to_testing: { min_scans: 5, min_true_positives: 3 }
  promote_to_stable: { min_scans: 20, min_confidence: 0.70 }
  auto_deprecate: { max_false_positive_rate: 0.95, min_samples: 20 }
```

## Why sentinella2?

Traditional SAST tools (Semgrep, CodeQL) find ~32% of real vulnerabilities. The most dangerous ones -- payment signature bypass, OTP backdoors, IDOR, fail-open middleware -- require understanding **what code is supposed to do**, not just what it looks like.

sentinella2 bridges this gap by combining deterministic rules with LLM-powered semantic analysis, guided by patterns from 93 real vulnerabilities found and fixed in production. And unlike static tools, it gets smarter every time you use it.

## License

MIT

---

<a id="中文"></a>

# 中文

## 功能特性

- **零配置扫描**: `sentinella2 scan ./project` 无需任何设置即可发现硬编码密钥、错误配置和常见漏洞
- **自适应学习**: 贝叶斯置信度校准从你的反馈中学习 -- 标注 50 条就能把噪音从 6,000 条降到 135 条真实问题
- **上下文记忆**: 声明项目上下文（"认证在 API Gateway 层处理"），扫描器自动跳过无关发现
- **模型无关深度审计**: 接入任意 LLM（Claude、GPT、GLM、Llama、Ollama）进行语义分析，发现传统 SAST 工具遗漏的漏洞
- **6 层纵深防御评估**: 受 FreeBSD 安全架构启发的纵深防御态势评估
- **跨项目知识迁移**: 在相同技术栈的项目间共享校准数据
- **可插拔**: CLI + MCP 服务器 + Go 库 + CI/CD 集成

## 快速开始

### 安装

```bash
# 从源码安装
go install github.com/perseworks/sentinella2/cmd/sentinella2@latest

# 或下载二进制文件
curl -sSL https://github.com/perseworks/sentinella2/releases/latest/download/sentinella2-$(uname -s)-$(uname -m) -o sentinella2
chmod +x sentinella2
```

### 扫描（无需 LLM）

```bash
sentinella2 scan ./my-project
```

### 深度审计（任意 LLM）

```bash
# Claude
sentinella2 audit ./my-project --provider anthropic --model claude-sonnet-4-6 --api-key $ANTHROPIC_API_KEY

# GPT
sentinella2 audit ./my-project --provider openai-compatible --base-url https://api.openai.com/v1 --model gpt-4o --api-key $OPENAI_API_KEY

# 本地 Ollama
sentinella2 audit ./my-project --provider openai-compatible --base-url http://localhost:11434/v1 --model llama3

# 智谱 GLM
sentinella2 audit ./my-project --provider openai-compatible --base-url https://open.bigmodel.cn/api/paas/v4 --model glm-4 --api-key $ZHIPU_API_KEY
```

### 纵深防御评估

```bash
sentinella2 check-layers ./my-project
```

## 自适应学习系统

sentinella2 超越了静态规则。它通过 5 组件自适应管道从你的反馈中学习：

### 学习循环

```
sentinella2 scan ./src             # 1. 扫描: 6,080 条发现 (冷启动)
sentinella2 memory add "auth at GW" # 2. 上下文: 声明项目事实
sentinella2 triage --batch 50      # 3. 标注: 引导式标注选择最高学习价值的发现
sentinella2 scan ./src             # 4. 重扫: 135 条发现 (已校准)
sentinella2 learn                  # 5. 学习: 发现模式，建议规则
```

### 核心组件

| 组件 | 功能 | 存储位置 |
|------|------|---------|
| **Finding Identity** | 稳定 ID，代码移动后不变（不含行号） | `.sentinella2/state.json` |
| **上下文记忆** | 用户声明的项目上下文，跳过无关发现 | `.sentinella2/memories.yaml` |
| **贝叶斯校准** | 按 (规则, 文件类型) 维护 Beta 分布 | `.sentinella2/calibration.json` |
| **置信度分级** | 发现分为 Confirmed (>70%) / Likely (30-70%) / Suspect (<30%) | 扫描输出 |
| **模式挖掘** | 聚类误报并自动建议规则 | `learn` 命令 |
| **规则生命周期** | 规则成熟度: experimental -> testing -> stable -> deprecated | 规则 YAML |
| **交叉验证** | 3+ 独立规则命中同一文件 -> 置信度提升 | 扫描后调整 |

### 技术栈先验迁移

新项目？没有反馈数据？sentinella2 检测技术栈并加载其他项目的校准数据：

```bash
$ sentinella2 scan ./my-new-nestjs-project
Detected tech stack: NestJS (confidence: 95%)
Loading 12 calibration buckets from shared pool...

$ sentinella2 kb calibration export --stack nestjs  # 导出共享
```

## 集成方式

### MCP 服务器（Claude Code、Cursor、VS Code）

```json
{
  "mcpServers": {
    "sentinella2": {
      "command": "sentinella2-mcp"
    }
  }
}
```

### Go 库

```go
import (
    "github.com/perseworks/sentinella2/pkg/scan"
    "github.com/perseworks/sentinella2/pkg/knowledge"
)

kb, _ := knowledge.LoadFromDir("./knowledge")
scanner := scan.New(
    scan.WithKnowledge(kb),
    scan.WithCalibration(calStore),
    scan.WithMemories(memStore),
    scan.WithCorrelation(scan.DefaultCorrelationConfig()),
)
result, _ := scanner.Scan(ctx, "./my-project")
```

### CI/CD

参见 [examples/github-action.yaml](examples/github-action.yaml) 和 [examples/gitlab-ci.yaml](examples/gitlab-ci.yaml)。

### Git Hooks

```bash
sentinella2 hooks install
```

## 知识库

### 7 类漏洞模式

| 模式 | 规则数 | 层级 | OWASP |
|------|--------|------|-------|
| 输入边界 | 5 | 1-2 | A03 |
| 认证流程 | 6 | 2-3 | A01, A02, A07 |
| 隔离 | 4 | 1 | A05 |
| 韧性 | 4 | 2-3 | A04, A07, A09 |
| 注入 | 3 | 1-2 | A03, A10 |
| 信任链 | 3 | 2-3 | A07, A08, A10 |
| 信息泄露 | 4 | 1 | A05, A09 |

### 三级检测

- **Tier 1**（约 32% 覆盖率）: 确定性正则匹配。零误报。无需 LLM。
- **Tier 2**（约 38% 覆盖率）: 带上下文的结构分析。需要代码理解。
- **Tier 3**（约 30% 覆盖率）: 语义分析。需要 LLM 推理。

### 6 层纵深防御

受 FreeBSD 安全架构启发：

| 层级 | 检查项 | FreeBSD 类比 |
|------|--------|-------------|
| 1. 入口层 | TLS、WAF、HSTS | pf 防火墙 |
| 2. 隔离层 | 命名空间、NetworkPolicy | jail + vnet |
| 3. 加固层 | 非 root、只读文件系统、seccomp | capsicum |
| 4. 访问控制层 | RBAC、认证中间件 | MAC 框架 |
| 5. 数据保护层 | 加密数据库、日志脱敏 | GELI |
| 6. 篡改检测层 | 审计追踪、配置指纹 | 不可变日志 |

## 命令参考

```
sentinella2 scan <path>               Tier 1 确定性扫描
sentinella2 audit <path>              LLM 深度审计
sentinella2 check-layers <path>       纵深防御评估
sentinella2 triage <path> --batch N   交互式标注（冷启动时引导式排序）
sentinella2 learn                     发现误报模式，建议规则
sentinella2 memory list|add|remove    管理项目上下文声明
sentinella2 kb feedback mark <id>     记录发现裁定
sentinella2 kb tune                   应用反馈驱动调优
sentinella2 kb calibration export     导出校准数据供共享
sentinella2 init                      创建默认配置
```

## 配置

在项目根目录创建 `.sentinella2.yaml`：

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

feedback:
  dir: ".sentinella2/feedback"
  auto_tune: true
  min_feedback: 5
  fp_threshold: 0.3

memory:
  file: ".sentinella2/memories.yaml"

rule_lifecycle:
  promote_to_testing: { min_scans: 5, min_true_positives: 3 }
  promote_to_stable: { min_scans: 20, min_confidence: 0.70 }
  auto_deprecate: { max_false_positive_rate: 0.95, min_samples: 20 }
```

## 为什么选择 sentinella2？

传统 SAST 工具（Semgrep、CodeQL）只能发现约 32% 的真实漏洞。最危险的那些——支付签名绕过、OTP 后门、IDOR、fail-open 中间件——需要理解**代码应该做什么**，而不仅仅是代码长什么样。

sentinella2 通过结合确定性规则与 LLM 语义分析来弥合这个差距，基于在生产环境中发现并修复的 93 个真实漏洞总结出的模式。而且与静态工具不同，它每次使用都会变得更聪明。

## 许可证

MIT
