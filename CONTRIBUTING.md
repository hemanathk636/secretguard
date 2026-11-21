# Contributing to SecretGuard

Thank you for your interest in making developer workstations and AI coding agents safer! SecretGuard is a community-driven, 100% Free and Open Source (FOSS) project dual-licensed under MIT and Apache-2.0.

---

## 🏛️ Codebase Architecture & The 3 Pillars

SecretGuard's codebase is written in native Rust with industry-standard cryptographic primitives (`aes-gcm`, `hkdf`, `hmac`, `rand_core`, `sha2`), engineered for sub-millisecond line interception (**~15 µs** average latency on in-memory command streams).

```text
src/
├── lib.rs              # Core engine, scan orchestrator & high-speed memory pipeline
├── main.rs             # CLI router & 3-pillar dispatch hierarchy
├── patterns.rs         # High-confidence regex patterns for cloud providers
├── entropy.rs          # Shannon entropy calculator H(X) with contextual awareness
├── encoding.rs         # In-memory Base64 & URL-percent encoded credential decoder
├── ghost.rs            # Client-Side polymorphic Ghost Token context virtualizer (AES-256-GCM encrypted)
├── immune.rs           # Automated containment, Slack revocation & guided console rotation deep-links
├── init.rs             # 10-Second automated workstation & agent setup wizard
├── completions.rs      # Native shell autocompletions generator (Zsh, Bash, Fish, PWSH)
├── shield/             # Pillar 1: Terminal pre-exec hooks, TLS swapper, screen cloaker
├── vault/              # Pillar 2: AES-256-GCM keystore, RFC 5869 HKDF, P2P mesh, honeytoken canaries
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

# Run all 70+ unit and integration tests across 27 test targets
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

## ⚡ Performance Tenet & Benchmark Methodology

SecretGuard's shell hook runs **synchronously prior to command execution** in developers' terminals.

### Benchmark Methodology:
- **Synthetic Micro-benchmark:** Measured on an Apple Silicon (M-series) / AMD Ryzen workstation with `cargo test --release` or synthetic timer loops over 1,000 synthetic commands (500 positive credential samples + 500 clean commands).
- **Latency Guarantee:** In-memory scanning average latency is ~15.68 µs (0.016 ms) per typical command line.
- **File I/O Notice:** Real-world codebase scans (`secretguard scan .`) and Git history scrubbing (`secretguard time-machine`) involve disk reads and Git object packing, and their throughput depends on filesystem speed and repository size.

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
