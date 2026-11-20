# Contributing to SecretGuard

Thank you for your interest in contributing to SecretGuard! 🦀

SecretGuard is a sub-millisecond, native Rust terminal secret interceptor and privacy guard for developers and autonomous AI agents. We welcome contributions from developers of all backgrounds.

## Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors. Please be respectful and constructive in all discussions.

## How to Contribute

### 1. Reporting Bugs & Requesting Token Signatures
If you encounter a false positive, a bypass, or want support for a new SaaS secret format (e.g., custom internal tokens, GCP, Azure, Datadog):
- Search the [existing issues](https://github.com/hemanathk636/secretguard/issues) to ensure it hasn't been reported.
- Open a new issue with reproducible command examples and expected output.

### 2. Local Development

Ensure you have Rust (edition 2021) installed:

```bash
# Clone the repository
git clone https://github.com/hemanathk636/secretguard.git
cd secretguard

# Run the test suite
cargo test

# Run the diagnostic health check
cargo run -- doctor

# Run the codebase scanner
cargo run -- scan src
```

### 3. Submitting Pull Requests
1. Fork the repository and create a new feature branch (`git checkout -b feature/new-token-rule`).
2. Implement your changes in `src/rules.rs` or `src/entropy.rs`.
3. Add corresponding test cases in `tests/test_suite.rs`.
4. Ensure all tests pass: `cargo test`.
5. Submit your PR with a clear description of the problem solved.

## Architecture Guidelines
- **Sub-Millisecond Speed:** All scans must execute in under 50 microseconds. Avoid blocking I/O or unnecessary heap allocations in the hot path.
- **100% Safe Rust:** We maintain zero `unsafe` blocks.
- **Zero Telemetry:** SecretGuard runs strictly offline. Never introduce external network requests.
