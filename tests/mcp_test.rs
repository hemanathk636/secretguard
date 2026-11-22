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
    assert_eq!(res.synthetic_text, sample);
}

#[test]
fn test_synthetic_mock_generation() {
    let engine = SecretGuardEngine::new();

    // Test AWS key length & prefix preservation
    let aws = "export AWS=AKIAIOSFODNN7EXAMPLE";
    let res = engine.scan_and_sanitize(aws);
    assert!(res.has_secret);
    assert!(res.synthetic_text.contains("AKIAFAKE"));
    assert_eq!(res.synthetic_text.len(), aws.len());

    // Test OpenAI Project Key preservation
    let openai = "OPENAI_API_KEY=sk-proj-123456789012345678901234567890123456789012345678";
    let res_ai = engine.scan_and_sanitize(openai);
    assert!(res_ai.has_secret);
    assert!(res_ai
        .synthetic_text
        .starts_with("OPENAI_API_KEY=sk-proj-TESTDUMMYMOCK"));
    assert_eq!(res_ai.synthetic_text.len(), openai.len());

    // Test GitHub Token preservation
    let gh = "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234";
    let res_gh = engine.scan_and_sanitize(gh);
    assert!(res_gh.has_secret);
    assert!(res_gh
        .synthetic_text
        .starts_with("GITHUB_TOKEN=ghp_TESTDUMMYMOCK"));
    assert_eq!(res_gh.synthetic_text.len(), gh.len());
}
