# SecretGuard Threat Model & Security Architecture

This document outlines the security assumptions, design principles, trust boundaries, and threat vectors considered in the design of **SecretGuard**.

---

## 1. Core Security Objectives

SecretGuard is engineered as a **local-first developer security firewall and zero-knowledge keystore**. Its primary objectives are:

1. **Pre-Execution Interception:** Prevent raw credentials (API keys, database URLs, tokens, private keys) from being executed in interactive terminal sessions, logged to shell history, or displayed in output streams.
2. **Pre-Commit Containment:** Stop accidental commits of sensitive files (`.env`, `.pem`, credentials) before they enter local or remote Git commit history.
3. **AI Agent Context Air-Gapping:** Protect developer secrets from being ingested by LLMs, AI coding assistants (Cursor, Claude Code, Copilot, Aider), and MCP tool calls through polymorphic "Ghost Tokens".
4. **Local Keystore Confidentiality:** Store workstation secrets in an authenticated, encrypted, zero-knowledge local vault without reliance on cloud infrastructure.

---

## 2. System Architecture & Components

```
                                 ┌───────────────────────────────────────────────┐
                                 │             DEVELOPER WORKSTATION             │
                                 └───────────────────────┬───────────────────────┘
                                                         │
                ┌────────────────────────────────────────┼────────────────────────────────────────┐
                ▼                                        ▼                                        ▼
   ┌───────────────────────────┐           ┌───────────────────────────┐           ┌───────────────────────────┐
   │    TERMINAL SHIELD        │           │     GIT / CI AUDITOR      │           │    AI AGENT & MCP GATE    │
   ├───────────────────────────┤           ├───────────────────────────┤           ├───────────────────────────┤
   │ • Bash extdebug line hook │           │ • Pre-commit fast hook    │           │ • Ghost Token Virtualizer │
   │ • Zsh preexec interceptor │           │ • Git commit history scan │           │ • Local loopback proxy    │
   │ • Screen cloaker & mask   │           │ • Trojan / BiDi detector  │           │ • MCP tool-call sanitizer │
   │ • Clipboard auto-purge    │           │ • Compliance cert auditor │           │ • Prompt injection radar  │
   └─────────────┬─────────────┘           └─────────────┬─────────────┘           └─────────────┬─────────────┘
                 │                                       │                                       │
                 └───────────────────────────────────────┼───────────────────────────────────────┘
                                                         │
                                                         ▼
                                       ┌───────────────────────────────────┐
                                       │   ZERO-KNOWLEDGE LOCAL VAULT      │
                                       ├───────────────────────────────────┤
                                       │ • 256-bit CSPRNG (OsRng)          │
                                       │ • RFC 5869 HKDF-SHA256 expansion  │
                                       │ • AES-256-GCM authentication      │
                                       │ • 0600 OS-isolated permissions    │
                                       │ • Atomic file replacement + fsync │
                                       └───────────────────────────────────┘
```

---

## 3. Trust Boundaries & Assumptions

### Trusted Elements
- **The Local Operating System Kernel & Hardware:** SecretGuard assumes the kernel, hardware RNG (`getrandom`/`BCryptGenRandom`), and standard system libraries are uncompromised.
- **The Running User Account:** SecretGuard runs with the privileges of the active developer user. It assumes other processes running under the same user UID are not actively running debuggers (`ptrace`) or reading process memory (`/proc/$PID/mem`).
- **Standard Cryptographic Primitives:** SecretGuard relies on vetted cryptographic implementations (`aes-gcm`, `sha2`, `hkdf`, `rand_core`).

### Untrusted Elements
- **Terminal Inputs & Copy-Paste Buffers:** Developer clipboard and shell commands can contain accidental secrets, copied tokens, or malicious command lines.
- **AI Coding Agent Contexts:** Third-party cloud LLM endpoints (Anthropic, OpenAI, etc.) that receive project files and context windows are considered public/external network boundaries.
- **Repository Commit History:** Git histories may contain historical secrets, hidden `.env` files, or malicious pull request code.
- **External Multi-User Directories:** Shared directories like `/tmp` or `/var/tmp` are untrusted. SecretGuard strictly forbids storing master keys or vaults in shared temporary storage.

---

## 4. Threat Vectors & Mitigations

| Threat Vector | Description | SecretGuard Mitigation |
| :--- | :--- | :--- |
| **Shell Command Execution Leak** | Developer runs `curl -H "Authorization: Bearer sk-..."` which persists in `~/.bash_history` and `ps aux`. | Native pre-exec hooks pipe commands via standard input (`printf '%s' "$cmd" \| secretguard check -`) to prevent exposing raw tokens in process listings (`ps`), aborting execution with exit code 1 *before* the command runs or reaches history. |
| **Accidental Terminal Echo** | Secret entered into terminal prompt is visible on screen or shoulder-surfed. | `secretguard vault set` disables echo via Unix `stty -echo` (with RAII restoration guard) and Windows `Read-Host -AsSecureString`. Fails closed if echo cannot be disabled. |
| **AI Context Ingestion** | AI coding assistant reads `.env` and sends production API keys to cloud LLMs in prompt context. | "Ghost Tokens" replace active credentials with polymorphic decoys (`sk-ghost-...`). Mappings are protected on disk via AES-256-GCM and strict 0600 file permissions with fail-closed persistence. |
| **P2P Team Keystore Exposure** | Weak master password allows dictionary or rainbow table attacks against shared team vault. | `secretguard mesh` derives 256-bit encryption keys using Argon2id with 16-byte cryptographically secure random salts per team member and CSPRNG master keys. |
| **Silent Scanner Fail-Open on Unreadable Files** | Permission errors, broken symlinks, or non-UTF8 binary blocks cause secrets scanner to silently skip files and report success. | Scanner tracks all I/O errors and skipped symlinks, processes binary streams without aborting, and exits with code 2 whenever any file cannot be inspected. |
| **Trojan Source & BiDi Unicode (CVE-2021-42574)** | Invisible characters or Bidirectional overrides change code meaning while hiding secrets or injection prompts. | `secretguard radar` scans files and prompts for zero-width characters and directional override Unicode codepoints (`U+202E`, `U+200B`, etc.). |
| **Symlink Hijacking Race** | Attacker creates symlink at `~/.secretguard/.master.key` pointing to a target file. | SecretGuard inspects metadata via `fs::symlink_metadata` (without following symlinks) and strictly rejects symlinks with a fatal error. |
| **Unix TOCTOU Directory Swapping** | Attacker swaps an ancestor directory component with a symlink during vault read/write operations. | Verified via `validate_unix_dir_descriptor` opening every ancestor directory with `O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC`, verifying ownership by active user or root, and rejecting group/world-writable permissions. |
| **Windows Directory Rename Race** | Concurrent thread or process attempts to rename an ancestor directory while vault is being created or loaded. | Mitigated via Windows directory anchoring: opens every ancestor with `FILE_FLAG_BACKUP_SEMANTICS \| FILE_FLAG_OPEN_REPARSE_POINT` without `FILE_SHARE_DELETE`, holding active locks until target is verified. |
| **Windows Insecure DACL / Custom Groups** | Attacker attempts to configure permissive ACLs granting modify/write rights to unprivileged users or custom groups. | Enforced by `inspect_dacl_and_owner`: validates owner SID (active user/Admins/SYSTEM), rejects NULL DACLs, unsupported ACE types, and any write/delete grants to World, Users, or custom groups. |
| **Terminal Setup Signal Races** | Signal (`SIGINT`/`SIGTERM`) arrives after terminal echo is disabled but before restoration handlers are armed. | Mitigated by POSIX `pthread_sigmask`: signals are masked in the calling thread during terminal setup and unmasked only after handlers and RAII guards are armed. |
| **Multi-Process Concurrency Races** | Competing OS processes simultaneously attempt to create or update the secure vault. | Handled via atomic replacement loops with exponential backoff (`ReplaceFileW` on Windows, atomic rename on Unix) and shared-deadline cleanup preventing orphaned worker processes. |
| **Multi-User `/tmp` Squatting** | Malicious local user pre-creates `/tmp/.secretguard` to capture keys or deny service. | SecretGuard enforces private per-user directories (`0o700` mode in `$HOME` or `$USERPROFILE`) and fails closed if inaccessible. Shared `/tmp` fallback is forbidden. |
| **Process Crash Vault Corruption** | Power failure or crash mid-write leaves the vault empty or unreadable. | New vault payloads are written to an unpredictable temporary file (`.vault.$PID.$RANDOM.tmp`), synced to disk, and atomically swapped into place via `fs::rename` with parent directory `fsync`. |
| **Binary Stream Corruption** | Child process outputs binary data (e.g. tarballs, images) during `vault run`. | Delimiter streaming validates UTF-8 validity via `std::str::from_utf8`. Valid text is redacted in real-time, while binary streams are preserved byte-for-byte without lossy replacement. |

---

## 5. Explicit Non-Goals & Limitations

To ensure transparency, SecretGuard defines the following explicit boundaries:

1. **Kernel/Root Level Compromise:** If an attacker has root/Administrator privileges, kernel modules, or hardware keyloggers on the developer machine, SecretGuard cannot protect keystore memory or terminal inputs.
2. **Unhooked Terminal Sessions:** If a developer explicitly launches a subshell without SecretGuard hooks loaded (e.g., `bash --noprofile`), commands in that subshell are outside the ambient shield.
3. **Encrypted or Heavily Obfuscated Custom Payloads:** SecretGuard's engine catches standard credential formats, 24+ provider patterns, Base64/Hex/URL-encoded secrets, and contextual high-entropy strings. Novel proprietary token formats with low entropy may require custom regex configuration in `secretguard.toml`.
4. **Third-Party Shell Extensions:** SecretGuard prioritizes compatibility with Zsh, Bash, Fish, and PowerShell. Custom non-POSIX esoteric shells are not supported by the ambient hook.
