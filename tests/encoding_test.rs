use secretguard::encoding::decode_base64;
use secretguard::SecretGuardEngine;

#[test]
fn test_base64_decode_utility() {
    let raw = "Hello, SecretGuard!";
    // "Hello, SecretGuard!" in base64: SGVsbG8sIFNlY3JldEd1YXJkIQ==
    let b64 = "SGVsbG8sIFNlY3JldEd1YXJkIQ==";
    let decoded = decode_base64(b64).expect("Failed to decode valid base64");
    assert_eq!(decoded, raw);
}

#[test]
fn test_base64_encoded_openai_key_detection() {
    let engine = SecretGuardEngine::new();

    // "sk-proj-1234567890abcdef1234567890abcdef" encoded in Base64:
    let b64_token = "c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==";
    let command = format!("echo {} | base64 -d", b64_token);

    let res = engine.scan_and_sanitize(&command);
    assert!(
        res.has_secret,
        "Engine failed to catch Base64-encoded OpenAI key"
    );
    assert!(res
        .matched_rules
        .iter()
        .any(|r| r.contains("Encoded (OpenAI API Key)")));
    assert!(!res.sanitized_text.contains(b64_token));
    assert!(res.sanitized_text.contains("[REDACTED_ENCODED_SECRET]"));
}

#[test]
fn test_base64_encoded_aws_key_detection() {
    let engine = SecretGuardEngine::new();

    // "AKIAIOSFODNN7EXAMPLE" encoded in Base64:
    let b64_token = "QUtJQUlPU0ZPRENON0VYQU1QTEU=";
    let command = format!("export AWS_B64_KEY={}", b64_token);

    let res = engine.scan_and_sanitize(&command);
    assert!(
        res.has_secret,
        "Engine failed to catch Base64-encoded AWS key"
    );
    assert!(res
        .matched_rules
        .iter()
        .any(|r| r.contains("Encoded (AWS Access Key)")));
    assert!(!res.sanitized_text.contains(b64_token));
}

#[test]
fn test_url_encoded_secret_detection() {
    let engine = SecretGuardEngine::new();

    // Database connection string with percent-encoded characters
    let url_encoded = "postgres%3A%2F%2Fadmin%3Amypassword123%40db.internal%3A5432%2Fprod";
    let command = format!("DATABASE_URL={}", url_encoded);

    let res = engine.scan_and_sanitize(&command);
    assert!(
        res.has_secret,
        "Engine failed to catch URL percent-encoded database connection string"
    );
}
