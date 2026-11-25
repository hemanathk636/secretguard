# Security Policy

SecretGuard is designed as mission-critical developer security infrastructure. We take the security, integrity, and privacy of SecretGuard, its dependencies, and the credentials it protects with the highest priority.

---

## Supported Versions

We actively maintain and provide security patches for the following versions:

| Version | Supported          | Security Status |
| ------- | ------------------ | --------------- |
| 1.0.x   | :white_check_mark: | Active (Current Release) |
| 0.3.x   | :white_check_mark: | Critical Security Fixes Only |
| < 0.3.0 | :x:                | Unsupported (Please upgrade) |

---

## Core Security Tenets

1. **Local-First & Zero Telemetry:** Core scanning, shell line interception, local vault encryption, Ghost Token generation, and audit logging run 100% offline with zero telemetry. Outbound HTTPS calls occur only when explicitly invoked (`immune`/`panic` upstream checks, delegated broker calls, or installer verification).
2. **In-Memory Execution:** Regex evaluation, entropy computation, and redaction occur in process memory without writing plaintext secrets to intermediate logs.
3. **Ghost Token Air-Gap:** AI coding agents are fed format-preserving decoy tokens; raw credentials are kept out of LLM prompt contexts and mediated through the local Security Broker.
4. **Authenticated Encryption:** Keystores are encrypted using AES-256-GCM authenticated encryption paired with Argon2id / HKDF-SHA256 key derivation.

---

## Threat Model & Trust Boundaries

### What SecretGuard Defends Against
- **Accidental Terminal & Shell History Leaks:** Intercepts credentials in shell buffers (`zsh`, `bash`, `powershell`) and `vault run` output streams before they hit history files or terminal logs.
- **Git & Codebase Leaks:** Pre-commit and repository scanning (`scan`, `audit git`) catch secrets before commits reach remotes.
- **AI Agent & MCP Context Exposure:** Isolates raw secrets behind Ghost Tokens, policy-enforced broker operations, repository allowlists, and kernel-verified IPC peer identity (`SO_PEERCRED` / `GetExtendedTcpTable`).
- **SSRF & URL Userinfo Spoofing:** Parses URLs once, rejects `@` userinfo, blocks private/loopback/metadata IPs, and pins resolved DNS destinations.
- **Filesystem Symlink / TOCTOU Races:** Uses descriptor-relative `openat(..., O_NOFOLLOW)` traversal on Unix and ancestor directory handle anchoring (`FILE_SHARE_DELETE` omitted) on Windows.

### What SecretGuard Does NOT Defend Against
- **Root / Administrator Compromise:** A privileged `root` or `Administrator` attacker can read process memory, replace binaries, or bypass OS file permissions.
- **Same-UID Kernel Debugging / Process Injection:** Processes running under the same OS user without separate OS-user isolation can attach debuggers (`ptrace`, `ReadProcessMemory`) unless restricted by OS-level policies.
- **Zero-Day / Unknown Custom Formats:** SecretGuard is a **defense-in-depth** tool; regex + entropy heuristics cannot guarantee 100% detection of arbitrary or custom-encoded secrets.

---

## Known Limitations

- **Installer Authenticity Verification (`install.sh`):** `install.sh` **fails closed** if `gh` CLI is unavailable (unless `SECRETGUARD_MINISIGN_PUBKEY` is explicitly pinned). SHA-256 checksums verify download integrity only, not release authenticity.
- **Continuous Agent Containment:** The agent firewall (`firewall`) inspects the wrapped command and output streams, but cannot intercept every subsequent child syscall or network packet outside the broker without OS sandboxing.
- **Upstream Revocation (`immune` / `panic`):** Local vault/lifecycle quarantine is immediate and offline, whereas upstream provider revocation/status checks require outbound HTTPS connectivity and provider API support.

---

## Release Verification Guide

Verify both **integrity** (SHA-256) and **authenticity/provenance** (Sigstore SLSA via GitHub CLI) before running any downloaded release binary:

### Linux / macOS
```bash
# 1. Integrity check
sha256sum -c secretguard-<TARGET>.tar.gz.sha256   # or: shasum -a 256 -c ...

# 2. Authenticity & SLSA provenance check
gh attestation verify secretguard-<TARGET>.tar.gz \
  --repo hemanathk636/secretguard \
  --signer-workflow hemanathk636/secretguard/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.0 \
  --deny-self-hosted-runners
```

### Windows (PowerShell)
```powershell
# 1. Integrity check
Get-FileHash .\secretguard-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Get-Content .\secretguard-x86_64-pc-windows-msvc.zip.sha256

# 2. Authenticity & SLSA provenance check
gh attestation verify .\secretguard-x86_64-pc-windows-msvc.zip `
  --repo hemanathk636/secretguard `
  --signer-workflow hemanathk636/secretguard/.github/workflows/release.yml `
  --source-ref refs/tags/v1.0.0 `
  --deny-self-hosted-runners
```

---

## Reporting a Vulnerability

If you discover a security vulnerability, bypass, or potential credential leak mechanism within SecretGuard:

**Please DO NOT open a public issue.** Public disclosure exposes active users before a patch can be verified and deployed.

### Method 1: GitHub Private Vulnerability Reporting (Recommended)
1. Navigate to the [SecretGuard Security Advisories tab](https://github.com/hemanathk636/secretguard/security/advisories).
2. Click **"Report a vulnerability"**.
3. Provide details of the finding, reproduction steps, affected operating systems/shells, and any proposed fixes.

### Method 2: Direct Contact
Send an encrypted report to the project maintainers with the subject `[SECURITY] SecretGuard Vulnerability Report`:
- Email: **hemanathk636@gmail.com**

Please include:
- A detailed description of the vulnerability.
- A proof-of-concept command, shell snippet, or git repository demonstrating the issue.
- Impact assessment (e.g., shell interceptor bypass, vault memory disclosure, false-negative in regex pattern).

---

## Response Timeline & SLA

We adhere to a coordinated vulnerability disclosure timeline:

- **Initial Acknowledgment:** Within **24 hours**.
- **Severity Assessment & Triage:** Within **48 hours**.
- **Fix & Patch Verification:** Within **7 days** (or sooner for high/critical vulnerabilities).
- **Public Disclosure & Release:** Coordinated with the reporter after binary release and Homebrew formula deployment.

Reporters who responsibly disclose security findings will be credited in our Release Notes and Security Hall of Fame (unless anonymity is requested).
