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

1. **Zero-Knowledge Architecture:** SecretGuard never transmits your raw credentials, shell history, or encryption keys to any external servers or telemetry backends.
2. **Sub-Millisecond In-Memory Execution:** All regex evaluation, entropy computation, and redaction occur in volatile process RAM with zero persistent intermediate disk logging.
3. **Ghost Token Air-Gap:** AI coding agents (Claude Code, Cursor, Aider, Devin) are fed polymorphic decoy tokens; LLM provider prompt contexts are strictly air-gapped from production credentials.
4. **Hardware-Isolated Cryptography:** Keystores are encrypted using AES-256-GCM authenticated encryption paired with Argon2id key derivation.

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
