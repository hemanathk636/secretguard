# 🚀 SecretGuard Launch Kit

## 1. Show HN (Hacker News) Post Template

**Title:**
> Show HN: SecretGuard – A 15µs Rust terminal guard that stops secrets before shell history

**Post Body:**
```markdown
Hey HN,

Every day, developers accidentally leak API keys (OpenAI keys, AWS credentials, database passwords) into three places:
1. Shell history (`~/.zsh_history`, `~/.bash_history`)
2. Screen shares (Zoom, Google Meet, OBS)
3. AI coding assistants (Claude Code, Cursor) that cache and log executed terminal commands into hidden project configs.

Existing tools like TruffleHog and GitGuardian are great, but they run at pre-commit or in CI/CD. By the time `git commit` runs, the key has already been executed, saved to disk in your shell history, and potentially broadcast on your screen.

We built **SecretGuard** (https://github.com/<your-username>/secretguard) to solve this:
- **Sub-millisecond dual-engine:** Written in pure Rust. It combines a high-confidence RegexSet (AWS, OpenAI, Anthropic, Stripe, GitHub, etc.) with a contextual Shannon entropy evaluator for database URLs and passwords.
- **Speed:** Average scan latency is 15.68 microseconds (0.016 ms) across a 1,000-sample benchmark. Zero perceptible typing lag.
- **Native Shell Hook:** Uses Zsh's `zshaddhistory` to intercept the command buffer. If a secret is detected, it strips the key from history and writes the sanitized version instead.
- **Stdout Stream Masking (`wrap`):** Run `secretguard wrap npm run dev` to mask live keys from ever flashing on your terminal screen during video calls or demos.
- **Zero Cloud / Zero Telemetry:** 100% client-side, single 1.5MB binary, no tracking, no external runtimes.

Installation:
curl -fsSL https://get.secretguard.dev | sh

Repo: https://github.com/<your-username>/secretguard

Would love your feedback on additional token formats, edge cases, and ideas!
```

---

## 2. Reddit Post (`r/rust`, `r/commandline`, `r/cybersecurity`)

**Title:**
> I built SecretGuard: A 15µs Rust CLI that prevents secrets from entering shell history and screen shares

**Subreddits:**
* `r/rust` (focus on the Rust implementation, RegexSet vs. entropy, and LTO binary size)
* `r/commandline` (focus on the Zsh/Bash hook mechanics and zero-lag feel)
* `r/cybersecurity` / `r/netsec` (focus on the Claude Code/terminal leak prevention angle)
