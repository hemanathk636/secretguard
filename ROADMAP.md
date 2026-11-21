# SecretGuard Engineering Roadmap (90-Day Execution Plan)

> **Vision:** The developer-first, local security firewall for secrets.  
> Protect API keys, credentials, and sensitive data across your terminal, Git workflow, and AI coding tools in under two minutes.

---

## 🧭 Strategic Positioning: What SecretGuard Is (and Is Not)

| Tool | Primary Focus | SecretGuard Differentiator |
| :--- | :--- | :--- |
| **Gitleaks** | Static Git history scanning | **Runtime & Execution Firewall:** SecretGuard prevents secrets from leaking into shell history, terminal output, and running processes before commits ever occur. |
| **TruffleHog** | Secret discovery & provider verification | **Local Developer Workflow Protection:** Integrates into active terminal sessions (`extdebug`/pre-exec), clipboard self-destruct, and local encrypted keystore. |
| **Infisical** | Centralized secrets management & cloud vault | **Zero-Cloud, Zero-Setup, Local-First:** 100% offline, zero external SaaS account required, runs in-memory with sub-millisecond overhead (15µs). |
| **Kingfisher** | Scanner & access mapping | **AI Agent & MCP Tool-Call Defense:** Polymorphic "Ghost Tokens" air-gap real credentials from LLM contexts (Cursor, Claude Code, Copilot, MCP servers). |

**Our Core Philosophy:**  
*Don't build another cloud secrets manager. Don't write another standalone git scanner.*  
**Build the indispensable local security layer that sits between the developer, their terminal, their code, and their AI agents.**

---

## 🗓️ 90-Day Phase Breakdown

### Phase 1: Stabilize & Build Trust (Days 1–15) — *Current Milestone (v0.3.6 achieved)*
- [x] Complete cryptographic hardening: genuine CSPRNG (`OsRng`) + RFC 5869 HKDF-SHA256 key derivation.
- [x] Fail-closed terminal echo suppression with Unix RAII `SttyEchoGuard` and Windows secure string input.
- [x] True atomic file replacement on Windows and Unix with parent directory `fsync` error propagation.
- [x] Eliminate shared `/tmp` fallback; enforce private `0o700` per-user directory with fail-closed semantics.
- [x] Preserve raw binary byte-for-byte in child output streaming (`vault run`).
- [x] Self-contained tests: dynamically initialized temporary Git repositories for source tarball & CI resilience.
- [x] Hard failure on GitHub Action checksum verification (`action.yml`).
- [x] Formally advertise MSRV in `Cargo.toml` (`rust-version = "1.78"`).
- [ ] Publish formal `THREAT_MODEL.md` and `ARCHITECTURE.md`.

---

### Phase 2: Effortless 2-Minute Onboarding (Days 16–30) — *Target: v0.4.0*
**Goal:** A new developer installs SecretGuard and protects their entire workstation in under 2 minutes.

- [ ] **Homebrew Formula (`brew install secretguard`)**:
  - Official tap and formula for macOS (Intel + Apple Silicon) and Linux.
- [ ] **Native Installer Scripts**:
  - `curl -fsSL https://secretguard.dev/install.sh | bash`
  - `irm https://secretguard.dev/install.ps1 | iex`
- [ ] **Instant Health Inspector (`secretguard doctor`)**:
  - Diagnostic command checking active shell hooks, `.git/hooks` installation, vault permissions, and PATH setup.
- [ ] **Interactive Onboarding Wizard (`secretguard init`)**:
  - Automatically detect active shells (Zsh, Bash, Fish, PowerShell) and append safe hook wrappers.
  - Automatically exclude `.secretguard/`, `.env*`, and AI agent config directories in global `.gitignore`.
- [ ] **Reproducible Release Automation**:
  - Automated GitHub Actions building cross-compiled release binaries with SHA-256 attestations for Linux (`x86_64`, `aarch64`), macOS (`x86_64`, `arm64`), and Windows (`x86_64`).

---

### Phase 3: The Killer Differentiator — AI Agent & MCP Firewall (Days 31–45) — *Target: v0.5.0*
**Goal:** Protect modern AI-assisted developer workflows where code and context are ingested by LLMs and agentic tools.

- [ ] **Ghost Token Virtualization Engine Expansion**:
  - Format-preserving polymorphic tokens (`sk-ghost-...`, `AKIA_GHOST_...`, `ghp_ghost_...`).
  - Safe replacement of active secrets in `.env` and configuration files when AI agents inspect files.
  - Automatic re-hydration at localhost reverse-proxy (`secretguard tun`) so real network calls succeed without exposing raw keys to prompt context.
- [ ] **MCP (Model Context Protocol) Security Proxy**:
  - Interceptor proxy for Claude Code, Cursor, and Windsurf MCP tool-calls (`mcp-proxy`).
  - Inspects file reads, command runs, and database query arguments passed into MCP tools.
  - Blocks prompt injection strings and redacts credential leaks in agent inputs and tool responses.
- [ ] **AI Context Air-Gap Verification**:
  - Benchmarks measuring latency (<1ms proxy overhead) and zero false negatives against AI prompt injection benchmarks.

---

### Phase 4: Developer Ecosystem & Integrations (Days 46–60) — *Target: v0.6.0*
**Goal:** Seamlessly fit into existing IDEs, editors, and continuous integration pipelines.

- [ ] **VS Code & Cursor Extension**:
  - Real-time inline squiggle warnings and quick-fix secret redaction / ghost token replacement in editor buffers.
- [ ] **Native Claude Code & CLI Agent Guardrails**:
  - Guard plugin for `claude` CLI and `aider` to intercept command executions before sub-processes run.
- [ ] **Standardized Output Formats**:
  - Full support for `--format json` and `--format sarif` across all scan commands for native GitHub Code Scanning integration.
- [ ] **Pre-Commit Framework Integration**:
  - Supported `.pre-commit-hooks.yaml` hook configurations with zero external dependencies.

---

### Phase 5: Community, Benchmarks & External Testers (Days 61–75) — *Target: v0.7.0*
**Goal:** Engage early developer adopters and validate detection accuracy on public datasets.

- [ ] **Public Benchmark Suite**:
  - Controlled performance and accuracy benchmarking against Gitleaks and TruffleHog using standard open-source synthetic corpora.
  - Latency validation: Sub-15 microsecond per-command terminal hook overhead.
- [ ] **Contributor Onboarding**:
  - Curate 15+ beginner-friendly `good-first-issue` tags on GitHub (new token patterns, docs, shell autocompletions).
  - Weekly releases addressing community bug reports and feedback.
- [ ] **Developer Documentation & Walkthroughs**:
  - Interactive browser demos, terminal recordings (`vhs`), and high-quality guides for Dev.to and Reddit r/rust / r/cybersecurity.

---

### Phase 6: Production Stable Release (Days 76–90) — *Target: v1.0.0*
**Goal:** Deliver a rock-solid, production-certified security tool for individual developers and engineering teams.

- [ ] Independent third-party security audit review.
- [ ] Stable CLI interface with Semantic Versioning 2.0 contract.
- [ ] Zero unhandled errors, deterministic exit codes, and cross-platform consistency.
- [ ] Public v1.0 Launch on Hacker News, Product Hunt, and Rust Foundation community channels.
