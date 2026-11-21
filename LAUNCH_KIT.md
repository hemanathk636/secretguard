# 🚀 SecretGuard Launch Kit (Copy & Paste Ready)

Use these curated launch posts to announce SecretGuard on Hacker News, Reddit, and Twitter/X.

---

## 1. 🟠 Hacker News (news.ycombinator.com)

**Type:** Show HN  
**Title:**
```text
Show HN: SecretGuard – Sub-millisecond terminal secret interceptor & AI firewall in Rust
```

**URL:** `https://github.com/hemanathk636/secretguard` or leave blank for text post.

**Body:**
```text
Hey HN,

We built SecretGuard (https://github.com/hemanathk636/secretguard) because traditional secret scanners (GitGuardian, TruffleHog, pre-commit hooks) run too late:
1. By the time `git commit` runs, the API key is already written to ~/.zsh_history in plain text.
2. If you use terminal-based AI coding agents (Claude Code, Cursor, Aider), the agent reads your .env files and sends raw keys directly to cloud LLMs.

SecretGuard sits directly in the shell line buffer between your keystroke and the OS, evaluating credentials via RegexSet and Shannon entropy in under 15 microseconds (0.016ms).

Key technical highlights in v0.3.0:
- Ghost Tokens: Zero-Knowledge LLM context virtualization. AI agents code against format-preserving decoy keys (`sk-ghost-...`), while our local in-flight swapper replaces them with real keys inside RAM when making live network calls. The cloud LLM never sees real credentials.
- Autonomous Self-Healing Immune Engine: Sub-second (<200ms) automated circuit breaker that calls provider revocation APIs, auto-rotates vault keys, and scrubs git commit trees before GitHub receives the packet.
- 10-Second Setup: Running `secretguard init` auto-configures your shell hooks (~/.zshrc / $PROFILE), pre-commit hooks (<0.02ms), and AI agent gitignore shields.
- Native Rust, zero unnecessary dependencies, 100% Free & Open Source (MIT OR Apache-2.0).

Install via Homebrew:
$ brew tap hemanathk636/tap && brew install secretguard
$ secretguard init

Interactive Web Sandbox: https://hemanathk636.github.io/secretguard/

Would love your feedback on the architecture and latency benchmarks!
```

---

## 2. 🔴 Reddit (r/rust, r/netsec, r/cybersecurity)

**Title:**
```text
SecretGuard: A sub-millisecond terminal secret interceptor and AI agent firewall written in Rust
```

**Body:**
```text
Hey everyone,

I'd like to share SecretGuard (v0.3.0), an open-source tool written in native Rust to solve the credential leak window in terminal workflows and AI agent environments.

Repo: https://github.com/hemanathk636/secretguard
Website & Live WebAssembly/Sandbox: https://hemanathk636.github.io/secretguard/

The Problem:
Most secret scanners trigger post-facto on git commit. But keys leak earlier:
- Stored permanently in shell history files (~/.zsh_history, ~/.bash_history).
- Captured on Zoom/Teams screen shares during live demos.
- Read into LLM context windows by tools like Claude Code or Cursor.

How SecretGuard solves this:
1. 15µs Pre-Exec Line Interception: Hooks Zsh/Bash/PowerShell preexec to sanitize credentials before commands touch disk.
2. Ghost Tokens (LLM Air-Gap): Replaces real credentials with polymorphic decoy tokens. The AI agent writes and tests code, but the model never sees the master API key.
3. Autonomous Immune System: Revokes leaked credentials via provider APIs (OpenAI, AWS, GitHub, Stripe) and rotates them into an AES-256-GCM hardware vault in under 200ms.
4. Dedicated 3 Pillars: `shield` (runtime interception), `vault` (zero-knowledge keystore), and `audit` (git time-machine history scrubber).

It is 100% Free & Open Source (dual MIT / Apache-2.0).

Install with:
cargo install secretguard
or
brew tap hemanathk636/tap && brew install secretguard

Feedback, issue reports, and new pattern requests are very welcome!
```

---

## 3. 🐦 Twitter / X Thread

**Tweet 1 (Hook):**
```text
We just released SecretGuard v0.3.0 🛡️

A sub-millisecond terminal secret interceptor and AI agent firewall written in native Rust.

Catches API keys in 15 microseconds before they touch ~/.zsh_history or reach cloud LLMs.

100% Free & Open Source: https://github.com/hemanathk636/secretguard 🧵👇
```

**Tweet 2 (Ghost Tokens):**
```text
When you use Claude Code or Cursor, the AI agent reads your .env files and sends raw credentials to the cloud LLM.

SecretGuard introduces "Ghost Tokens" 👻:
Decoy tokens that AI agents use to code and run tests. Your real credentials NEVER enter the prompt context window.
```

**Tweet 3 (Autonomous Immune Engine):**
```text
Traditional scanners show red text saying you leaked a key.

SecretGuard v0.3.0 features an Autonomous Immune Engine 🧬:
Calls provider revocation APIs, rotates new keys into an encrypted vault, and sanitizes git trees in <200ms with zero human touch.
```

**Tweet 4 (Get Started):**
```text
Try the 10-second setup:
$ brew tap hemanathk636/tap && brew install secretguard
$ secretguard init

Try the interactive sandbox: https://hemanathk636.github.io/secretguard/

GitHub: https://github.com/hemanathk636/secretguard
⭐ Stars & PRs are welcome!
```
