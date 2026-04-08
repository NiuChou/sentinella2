# GitHub Description / GitHub 项目描述

## Short Description (for repo "About" field, max 350 chars)

**English:**

Security audit engine that learns from your feedback. Bayesian confidence calibration turns 6,000 noisy findings into 135 real issues. Combines deterministic regex rules with LLM-powered semantic analysis. Model-agnostic. Zero-config. Born from 93 real-world vulnerabilities.

**中文:**

自适应安全审计引擎，从用户反馈中持续学习。贝叶斯置信度校准将 6,000 条噪音精炼为 135 条真实问题。融合确定性正则规则与 LLM 语义分析，模型无关、零配置。源自 93 个生产环境真实漏洞。

---

## Topics / 标签

```
security  sast  vulnerability-scanner  bayesian  llm  go  
security-audit  knowledge-base  adaptive-learning  mcp  
freebsd  owasp  defense-in-depth  cli-tool
```

---

## One-liner (for badges / social sharing)

**EN:** sentinella2 — the security scanner that gets smarter every time you use it

**中文:** sentinella2 — 越用越准的安全扫描引擎

---

## Extended Description (for GitHub README social preview / blog / ProductHunt)

### English

**sentinella2** is an open-source security audit engine with an adaptive knowledge base, born from a 93-vulnerability production audit and FreeBSD Security Advisory analysis.

Traditional SAST tools report thousands of findings and never learn which ones you care about. sentinella2 is different:

- **It learns.** A Bayesian confidence system calibrates every finding based on your feedback. Label 50 findings, and the next scan drops noise by 97%.
- **It remembers.** Declare project context ("auth is at API Gateway") and the scanner stops reporting what you've already handled.
- **It transfers.** Switch to a new project with the same tech stack? Your calibration data follows.
- **It works with any LLM.** Claude, GPT, GLM, Llama, Ollama — or no LLM at all for deterministic-only scanning.

Built as a single Go binary with zero external dependencies beyond `gopkg.in/yaml.v3`. Ships as CLI, MCP server, Go library, and CI/CD integration.

### 中文

**sentinella2** 是一款开源自适应安全审计引擎，源自一次涵盖 93 个漏洞的全平台生产审计和 FreeBSD 安全公告分析。

传统 SAST 工具报告数千条发现，却永远不会学习哪些是你真正关心的。sentinella2 不同：

- **它会学习。** 贝叶斯置信度系统根据你的反馈校准每一条发现。标注 50 条，下次扫描噪音降低 97%。
- **它有记忆。** 声明项目上下文（"认证在 API Gateway 层处理"），扫描器自动跳过你已处理的内容。
- **它能迁移。** 切换到相同技术栈的新项目？校准数据自动跟随。
- **它兼容任意 LLM。** Claude、GPT、GLM、Llama、Ollama——或者完全不用 LLM，仅做确定性扫描。

构建为单一 Go 二进制文件，除 `gopkg.in/yaml.v3` 外零外部依赖。支持 CLI、MCP 服务器、Go 库和 CI/CD 集成。
