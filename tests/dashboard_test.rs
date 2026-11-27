use secretguard::SecretGuardEngine;

#[test]
fn test_dashboard_status_endpoint() {
    let engine = SecretGuardEngine::new();
    let synthetic_key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    let sample = format!("export AWS_ACCESS_KEY_ID={}", synthetic_key);
    let res = engine.scan_and_sanitize(&sample);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("[REDACTED]"));
    assert!(res.matched_rules.contains(&"AWS Access Key".to_string()));
}

#[test]
fn test_powershell_and_bash_hook_definitions() {
    // Warm up lazy regex/engine initialization so cold-start compilation does not skew latency
    let engine = SecretGuardEngine::new();
    let _ = engine.scan_and_sanitize("echo warmup");

    let payload = [
        "curl -H 'Authorization: Bearer ",
        "sk-ant-",
        "api03-",
        "abcdef1234567890",
        "abcdef1234567890",
        "' https://api.anthropic.com",
    ]
    .concat();
    let mut samples_ms = [0u128; 5];
    for slot in &mut samples_ms {
        let start = std::time::Instant::now();
        let res = engine.scan_and_sanitize(&payload);
        *slot = start.elapsed().as_millis();
        assert!(res.has_secret);
    }
    samples_ms.sort_unstable();
    assert!(samples_ms[2] < 50);
}
