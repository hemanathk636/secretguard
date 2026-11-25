# SecretGuard Engineering Roadmap (90-Day Execution Plan)

> **Vision:** The developer-first, local security firewall for secrets.  
> Protect API keys, credentials, and sensitive data across your terminal, Git workflow, and AI coding tools in under two minutes.

---

## 🧭 Strategic Positioning: What SecretGuard Is (and Is Not)

| Tool | Primary Focus | SecretGuard Differentiator |
| :--- | :--- | :--- |
| **Gitleaks** | Static Git history scanning | **Runtime & Execution Firewall:** SecretGuard prevents secrets from leaking into shell history, terminal output, and running processes before commits ever occur. |
| **TruffleHog** | Secret discovery & provider verification | **Local Developer Workflow Protection:** Integrates into active terminal sessions (`extdebug`/pre-exec), clipboard self-destruct, and local encrypted keystore. |
| **Infisical** | Centralized secrets management & cloud vault | **Zero-Cloud, Local-First:** Core scanning, vault encryption, and shell hooks run 100% offline with zero telemetry or SaaS account; optional `immune`/`panic` upstream revocation checks call provider APIs only when explicitly invoked. |
| **Kingfisher** | Scanner & access mapping | **AI Agent & MCP Tool-Call Defense:** Polymorphic "Ghost Tokens" air-gap real credentials from LLM contexts (Cursor, Claude Code, Copilot, MCP servers). |

**Our Core Philosophy:**  
*Don't build another cloud secrets manager. Don't write another standalone git scanner.*  
**Build the indispensable local security layer that sits between the developer, their terminal, their code, and their AI agents.**

---

## 🏁 Current Status: `v1.0.0` Released

SecretGuard `v1.0.0` is published with cross-platform CI (`ubuntu-latest`, `macos-latest`, `windows-latest`), Sigstore/SLSA build provenance, AES-256-GCM + Argon2id local vault, shell hooks, authenticated IPC/MCP broker, and immutable Git-object release packaging.

---

## 🎯 Next Milestone: `v1.0.1` — First 10 Real Users & Independent Review (30-Day Plan)

**Focus:** Real-world reliability, external security review, compatibility fixes, and documentation clarity. No speculative feature bloat.

| Period | Goal |
| :--- | :--- |
| **Days 1–3** | Documentation and public claims cleanup (`README.md`, `ROADMAP.md`, `LAUNCH_KIT.md`). |
| **Days 4–10** | Recruit 10 developers using terminals and AI coding agents to test `secretguard init`, scanning, vault, and agent protection on real machines. |
| **Days 11–20** | Collect feedback, installation issues, false positives, and reproduce reported defects. |
| **Days 21–25** | Fix confirmed bugs, compatibility issues, and external security review findings. |
| **Days 26–30** | Prepare `v1.0.1` release only if confirmed fixes warrant it. |

---

## 📜 Completed Pre-1.0 Milestones

### Phase 1: Stabilize & Build Trust — *Completed (`v0.3.6` → `v1.0.0`)*
- [x] Complete cryptographic hardening: genuine CSPRNG (`OsRng`) + RFC 5869 HKDF-SHA256 key derivation.
- [x] Fail-closed terminal echo suppression with Unix RAII `SttyEchoGuard` and Windows secure string input.
- [x] True atomic file replacement on Windows and Unix with parent directory `fsync` error propagation.
- [x] Eliminate shared `/tmp` fallback; enforce private `0o700` per-user directory with fail-closed semantics.
- [x] Preserve raw binary byte-for-byte in child output streaming (`vault run`).
- [x] Self-contained tests: dynamically initialized temporary Git repositories for source tarball & CI resilience.
- [x] Hard failure on GitHub Action checksum verification (`action.yml`).
- [x] Formally advertise MSRV in `Cargo.toml` (`rust-version = "1.78"`).
- [x] Automated cross-platform release builds + Sigstore/SLSA provenance (`release.yml`).
- [x] Local Security Broker, authenticated IPC/MCP, and fail-closed `install.sh` provenance verification.

### Future / Post-v1.0.1 Backlog (Deferred Until Real-User Validation)
- Formal `THREAT_MODEL.md` and `ARCHITECTURE.md`
- Standalone `brew` tap / `install.ps1` parity and `.pre-commit-hooks.yaml`
- VS Code / Cursor extension and SARIF output refinements
- Independent third-party security audit review
