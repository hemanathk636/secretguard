use secretguard::SecretGuardEngine;

#[test]
fn test_mcp_engine_redaction() {
    let engine = SecretGuardEngine::new();
    let sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let res = engine.scan_and_sanitize(sample);

    assert!(res.has_secret);
    assert!(!res.sanitized_text.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(res.sanitized_text.contains("[REDACTED]"));
}

#[test]
fn test_mcp_clean_input() {
    let engine = SecretGuardEngine::new();
    let sample = "git status && cargo build --release";
    let res = engine.scan_and_sanitize(sample);

    assert!(!res.has_secret);
    assert_eq!(res.sanitized_text, sample);
}
