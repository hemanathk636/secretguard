# Contributing to SecretGuard

Thank you for your interest in making developer workstations and AI coding agents safer! SecretGuard is a community-driven, 100% Free and Open Source (FOSS) project dual-licensed under MIT and Apache-2.0.

---

## 🏛️ Codebase Architecture & The 3 Pillars

SecretGuard's codebase is written in native Rust with zero unnecessary dependencies, engineered to run in **under 15 microseconds (0.016ms)**.

```text
src/
├── lib.rs              # Core engine, scan orchestrator & high-speed memory pipeline
├── main.rs             # CLI router & 3-pillar dispatch hierarchy
├── patterns.rs         # High-confidence regex patterns for cloud providers
├── entropy.rs          # Shannon entropy calculator H(X) with contextual awareness
├── ghost.rs            # Zero-Knowledge polymorphic Ghost Token context virtualizer
├── immune.rs           # Autonomous self-healing containment & revocation circuit breaker
├── init.rs             # 10-Second automated workstation & agent setup wizard
├── completions.rs      # Native shell autocompletions generator (Zsh, Bash, Fish, PWSH)
├── shield/             # Pillar 1: Terminal pre-exec hooks, TLS swapper, screen cloaker
├── vault/              # Pillar 2: AES-256-GCM keystore, P2P mesh, honeytoken canaries
└── audit/              # Pillar 3: Codebase scanner, git time-machine, Docker layer X-Ray
```

---

## 🚀 Development Quickstart

### Prerequisites
- [Rust & Cargo](https://rustup.rs/) (edition 2021, MSRV 1.70+)
- `git`

### Build & Run
```bash
# Clone the repository
git clone https://github.com/hemanathk636/secretguard.git
cd secretguard

# Build in debug mode
cargo build

# Run all 50+ unit and integration tests
cargo test

# Build optimized release binary
cargo build --release
```

---

## 🧩 Adding a New Secret Pattern (How-To)

One of the most valuable contributions is expanding SecretGuard's coverage for cloud providers and API keys.

1. Open `src/patterns.rs`.
2. Add your pattern to `get_high_confidence_patterns()`:
```rust
SecretPattern {
    name: "Supabase Service Role Key",
    description: "Supabase Backend Service Role JWT",
    regex: Regex::new(r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b").unwrap(),
},
```
3. Add a unit test in `tests/test_suite.rs` with an example mock token.
4. Run `cargo test` to ensure it passes with zero regressions.

---

## ⚡ Performance Tenet: The 15-Microsecond Rule

SecretGuard runs **synchronously on every keystroke/command** in developers' terminals. 

To maintain our sub-millisecond guarantee:
- Avoid heap allocations in hot paths (`scan_and_sanitize`).
- Prefer pre-compiled `RegexSet` or static regexes (`lazy_static`).
- Do not make synchronous network calls during command-line interception.

---

## 📋 Pull Request Guidelines

1. **Keep it focused:** One feature, pattern, or bugfix per PR.
2. **Add automated tests:** Every new feature or pattern must include corresponding tests in `tests/`.
3. **Format & Lint:**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   ```
4. **Pass all tests:**
   ```bash
   cargo test
   ```

---

## 📜 Code of Conduct

We are dedicated to providing a welcoming, diverse, and harassment-free environment for everyone. Please be respectful, constructive, and kind in all issues, pull requests, and discussions.
