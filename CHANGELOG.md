# Changelog

All notable changes to SecretGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `SECURITY.md` Threat Model, Trust Boundaries, Known Limitations, and Release Verification Guide.
- `.github/ISSUE_TEMPLATE/false_positive.yml` and updated `bug_report.yml` for `v1.0.0`.
- `.github/dependabot.yml` for automated Cargo and GitHub Actions dependency updates.

### Changed
- Clarified offline core vs. optional upstream network boundaries and synthetic benchmark scope across `README.md`, `ROADMAP.md`, and `LAUNCH_KIT.md`.

## [1.0.0] - 2026-11-25

### Added
- Cross-platform CI (`ubuntu-latest`, `macos-latest`, `windows-latest`) with `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo audit`.
- Automated GitHub Releases with Sigstore/SLSA build provenance (`actions/attest-build-provenance`) and SHA-256 checksums.
- Immutable Git-object release packager and artifact security scanner (`scripts/package_release.py`) with full-block PEM and exact SHA-256 fixture allowlisting.
- Local Security Broker, authenticated IPC with bounded worker pools (`16` workers, `64 KiB` request limit, `5s` I/O timeouts), and tamper-evident HMAC audit ledger.

### Security & Fixes
- Fixed Apple Silicon (`aarch64-apple-darwin`) variadic C ABI declarations for `open` and `openat` in `src/vault.rs`.
- Enforced descriptor-relative `openat(..., O_NOFOLLOW)` traversal on Unix and ancestor directory handle anchoring on Windows.
- Made `install.sh` authenticity verification mandatory (fail-closed via `gh attestation verify` or explicitly pinned `SECRETGUARD_MINISIGN_PUBKEY`).
- Rejected URL userinfo (`@`) and enforced strict repository allowlists in policy evaluation.
- Removed runtime `.secretguard/` state from release packaging and enforced NFKC + case-insensitive forbidden-path checks.

[Unreleased]: https://github.com/hemanathk636/secretguard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hemanathk636/secretguard/releases/tag/v1.0.0
