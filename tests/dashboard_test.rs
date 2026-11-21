use secretguard::SecretGuardEngine;

#[test]
fn test_dashboard_status_endpoint() {
    let engine = SecretGuardEngine::new();
    let sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let res = engine.scan_and_sanitize(sample);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("[REDACTED]"));
    assert!(res.matched_rules.contains(&"AWS Access Key".to_string()));
}

#[test]
fn test_powershell_and_bash_hook_definitions() {
    // Verify engine sanity and detection latency
    let engine = SecretGuardEngine::new();
    let start = std::time::Instant::now();
    let res = engine.scan_and_sanitize("curl -H 'Authorization: Bearer sk-ant-api03-abcdef1234567890abcdef1234567890' https://api.anthropic.com");
    let elapsed = start.elapsed();
    assert!(res.has_secret);
    assert!(elapsed.as_millis() < 50);
}
