use secretguard::SecretGuardEngine;

#[test]
fn test_clean_commands() {
    let engine = SecretGuardEngine::new();
    let clean_cases = vec![
        "git commit -m 'Initial commit'",
        "cargo build --release",
        "npm run test",
        "curl https://api.github.com/users/octocat",
        "ls -la /var/log",
        "docker run -p 8080:80 nginx",
    ];

    for cmd in clean_cases {
        let res = engine.scan_and_sanitize(cmd);
        assert!(!res.has_secret, "Falsely flagged clean command: {}", cmd);
        assert_eq!(res.sanitized_text, cmd);
    }
}

#[test]
fn test_openai_key_redaction() {
    let engine = SecretGuardEngine::new();
    let prefix = "sk-proj";
    let token = format!("{}-1234567890abcdef1234567890abcdef", prefix);
    let raw = format!("curl -H 'Authorization: Bearer {}' https://api.openai.com", token);
    let res = engine.scan_and_sanitize(&raw);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("sk-p[REDACTED]"));
    assert!(!res.sanitized_text.contains("1234567890abcdef1234567890abcdef"));
}

#[test]
fn test_aws_key_redaction() {
    let engine = SecretGuardEngine::new();
    let prefix = "AKIA";
    let token = format!("{}IOSFODNN7EXAMPLE", prefix);
    let raw = format!("aws s3 sync . s3://mybucket --profile default # {}", token);
    let res = engine.scan_and_sanitize(&raw);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("AKIA[REDACTED]"));
}

#[test]
fn test_github_token_redaction() {
    let engine = SecretGuardEngine::new();
    let prefix = "ghp";
    let token = format!("{}_1234567890abcdef1234567890abcdef1234", prefix);
    let raw = format!("git push https://{}@github.com/repo.git", token);
    let res = engine.scan_and_sanitize(&raw);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("ghp_[REDACTED]"));
}

#[test]
fn test_database_url_redaction() {
    let engine = SecretGuardEngine::new();
    let raw = "psql postgresql://postgres:mypassword123@localhost:5432/mydb";
    let res = engine.scan_and_sanitize(raw);
    assert!(res.has_secret);
    assert!(res.sanitized_text.contains("[REDACTED]"));
}

#[test]
fn test_contextual_password_redaction() {
    let engine = SecretGuardEngine::new();
    let raw = "export DB_PASSWORD=X9#kLm!2$pQ8wZ10_live";
    let res = engine.scan_and_sanitize(raw);
    assert!(res.has_secret);
    assert!(!res.sanitized_text.contains("X9#kLm!2$pQ8wZ10_live"));
}

#[test]
fn test_cloud_providers_expansion() {
    let engine = SecretGuardEngine::new();

    // 1. NPM Automation Token
    let npm_token = format!("{}_{}", "npm", "1234567890abcdef1234567890abcdef1234");
    let npm_raw = format!("npm publish --token {}", npm_token);
    let res = engine.scan_and_sanitize(&npm_raw);
    assert!(res.has_secret);
    assert!(res.matched_rules.contains(&"NPM Access Token".to_string()));

    // 2. Resend API Key
    let resend_token = format!("{}_{}", "re", "1234567890abcdef1234567890abcdef");
    let resend_raw = format!("RESEND_API_KEY={}", resend_token);
    let res = engine.scan_and_sanitize(&resend_raw);
    assert!(res.has_secret);
    assert!(res.matched_rules.contains(&"Resend API Key".to_string()));

    // 3. Twilio API Key
    let twilio_token = format!("{}{}", "SK", "1234567890abcdef1234567890abcdef");
    let twilio_raw = format!("TWILIO_API_KEY={}", twilio_token);
    let res = engine.scan_and_sanitize(&twilio_raw);
    assert!(res.has_secret);
    assert!(res.matched_rules.contains(&"Twilio API Key".to_string()));

    // 4. Shopify Token
    let shopify_token = format!("{}_{}", "shpat", "1234567890abcdef1234567890abcdef");
    let shopify_raw = format!("SHOPIFY_TOKEN={}", shopify_token);
    let res = engine.scan_and_sanitize(&shopify_raw);
    assert!(res.has_secret);
    assert!(res.matched_rules.contains(&"Shopify Token".to_string()));

    // 5. Linear API Key
    let linear_token = format!("{}_{}", "lin_api", "1234567890abcdef1234567890abcdef12345678");
    let linear_raw = format!("LINEAR_KEY={}", linear_token);
    let res = engine.scan_and_sanitize(&linear_raw);
    assert!(res.has_secret);
    assert!(res.matched_rules.contains(&"Linear API Key".to_string()));
}
