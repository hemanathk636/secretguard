# 🚀 SecretGuard Launch Kit (Tuesday Peak Launch)

## 1. Show HN (Hacker News) Post
**Target Window:** Tuesday, 8:00 AM – 9:00 AM PST (9:30 PM – 10:30 PM IST)  
**Submission URL:** https://news.ycombinator.com/submit  

### Submission Fields:
* **Title:**
  `Show HN: SecretGuard – A 15µs Rust line-hook that stops secrets before .zsh_history`
* **URL:**
  `https://github.com/hemanathk636/secretguard`
* **Text:** (Leave empty if submitting URL directly on HN, OR immediately add this as the first comment on your submission):

```markdown
Hey HN,

I built SecretGuard (https://github.com/hemanathk636/secretguard) because I was tired of secret scanners running *after* the damage was already done.

Traditional scanners (GitGuardian, TruffleHog, pre-commit hooks) run at `git commit` or inside CI pipelines. By the time they trigger:
1. The secret is already written to persistent disk in `~/.zsh_history` or `~/.bash_history`.
2. Database credentials were shown in plain text on screen shares (Zoom, Meet, demos).
3. Local AI coding assistants (Claude Code, Cursor) cached the raw command in `.claude/settings.local.json`.

### How It Works in Rust (0.016ms Latency):
SecretGuard hooks directly into the shell line buffer (Zsh, Bash, PowerShell). The instant you press Enter:

1. **Dual-Tier Detection:**
   - **Tier 1:** Compiled in-memory `regex::RegexSet` matching known SaaS signatures (OpenAI `sk-proj`, AWS `AKIA`, GitHub `ghp_`, Stripe, Slack, Postgres URIs).
   - **Tier 2:** Contextual Shannon Entropy Evaluator ($H \ge 3.6$) detecting raw high-entropy passwords while eliminating false positives like UUIDs and Git commit hashes.

2. **Sub-Millisecond Speed:**
   - Benchmarked across 1,000 synthetic commands: **15.68 µs (0.016 ms)** average scan latency.
   - Built with `--release` flags: `opt-level = 3`, `lto = true`, `codegen-units = 1`, and `panic = "abort"`.
   - Single **1.56 MB** binary with zero external dependencies and zero perceptible typing delay.

3. **In-Place Redaction:**
   - If a secret is detected, it scrubs the credential on the fly before it ever touches `~/.zsh_history`.

### Core Features:
- `secretguard hook zsh` — Attaches the live terminal interceptor.
- `secretguard audit` — Scans thousands of past commands in history in milliseconds.
- `secretguard clean-history` — Atomically cleans leaked history entries with automatic timestamped backups (`.zsh_history.bak`).
- `secretguard protect-agent` — Audits Claude Code, Cursor, and MCP directories to prevent accidental Git pushes.
- `secretguard wrap <cmd>` — Cloaks stdout streams in real-time during screen shares and Zoom calls.

### Install:
Via Homebrew (macOS / Linux):
```bash
brew tap hemanathk636/tap && brew install secretguard
```

Via One-Liner Script:
```bash
curl -fsSL https://raw.githubusercontent.com/hemanathk636/secretguard/main/install.sh | bash
```

- GitHub: https://github.com/hemanathk636/secretguard
- Interactive Sandbox & Benchmarks: https://hemanathk636.github.io/secretguard/

I would love to get HN's thoughts on the Rust architecture, the entropy heuristics, and any edge cases you'd recommend handling!
```

---

## 2. Reddit Post (`r/rust` & `r/commandline`)
*(Account `u/hemanath_dev` is now > 48 hours old and matured)*

* **Title:** `SecretGuard: A 15µs line-hook in Rust that stops secrets before ~/.zsh_history`
* **Flair:** `project`
* **Link:** `https://hemanathk636.github.io/secretguard/`
