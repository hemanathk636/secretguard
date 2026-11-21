use secretguard::pii::PiiScrubber;
use secretguard::SecretGuardEngine;

#[test]
fn test_scrub_credit_cards() {
    let engine = SecretGuardEngine::new();
    let prompt = "Please process refund for card 4111111111111111 today.";
    let res = PiiScrubber::scrub_pii(prompt, &engine);
    assert!(res.has_pii);
    assert!(res.sanitized_text.contains("[REDACTED_CC]"));
    assert!(!res.sanitized_text.contains("4111111111111111"));
}

#[test]
fn test_scrub_ssn() {
    let engine = SecretGuardEngine::new();
    let prompt = "User SSN is 123-45-6789 for identity verification.";
    let res = PiiScrubber::scrub_pii(prompt, &engine);
    assert!(res.has_pii);
    assert!(res.sanitized_text.contains("[REDACTED_SSN]"));
    assert!(!res.sanitized_text.contains("123-45-6789"));
}
