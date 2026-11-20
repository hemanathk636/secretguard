use secretguard::clipboard::ClipboardGuardian;
use secretguard::SecretGuardEngine;

#[test]
fn test_clipboard_payload_sanitizer() {
    let engine = SecretGuardEngine::new();

    let safe_text = "npm install express";
    let (is_leak, sanitized) = ClipboardGuardian::sanitize_clipboard_payload(safe_text, &engine);
    assert!(!is_leak);
    assert_eq!(sanitized, safe_text);

    let exposed_token = "export OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef1234567890";
    let (detected, scrubbed) = ClipboardGuardian::sanitize_clipboard_payload(exposed_token, &engine);
    assert!(detected);
    assert!(scrubbed.contains("[REDACTED]"));
    assert!(!scrubbed.contains("1234567890abcdef"));
}
