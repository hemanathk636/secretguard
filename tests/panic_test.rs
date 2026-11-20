use secretguard::panic::{get_quarantine_path, identify_revocation_info, quarantine_secret};
use std::fs;

#[test]
fn test_panic_identifies_openai_revocation() {
    let key = "sk-proj-1234567890abcdef1234567890abcdef1234567890";
    let rev = identify_revocation_info(key).expect("Should identify OpenAI");
    assert_eq!(rev.provider, "OpenAI");
    assert!(rev.dashboard_url.contains("platform.openai.com"));
}

#[test]
fn test_panic_identifies_github_revocation() {
    let key = "ghp_1234567890abcdef1234567890abcdef1234";
    let rev = identify_revocation_info(key).expect("Should identify GitHub");
    assert_eq!(rev.provider, "GitHub");
    assert!(rev.api_revoke_cmd.is_some());
    assert!(rev.api_revoke_cmd.unwrap().contains("api.github.com"));
}

#[test]
fn test_panic_identifies_aws_and_stripe() {
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let rev_aws = identify_revocation_info(aws).expect("Should identify AWS");
    assert!(rev_aws.provider.contains("AWS"));

    let stripe = "sk_test_1234567890abcdef1234567890";
    let rev_stripe = identify_revocation_info(stripe).expect("Should identify Stripe");
    assert_eq!(rev_stripe.provider, "Stripe");
}

#[test]
fn test_panic_quarantines_secret() {
    let test_secret = "sk-test-quarantine-key-999";
    quarantine_secret(test_secret);

    let qpath = get_quarantine_path();
    assert!(qpath.exists());
    let content = fs::read_to_string(&qpath).unwrap();
    assert!(content.contains("REVOKED_HASH:"));
}
