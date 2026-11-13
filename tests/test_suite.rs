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
