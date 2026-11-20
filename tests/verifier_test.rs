use secretguard::verifier::{KeyStatus, KeyVerifier};

#[test]
fn test_verify_openai_tokens() {
    let mock = "sk-proj-FAKETOKEN0000000000000000000000";
    let res = KeyVerifier::verify_key(mock);
    assert_eq!(res.key_type, "OpenAI API Key");
    matches!(res.status, KeyStatus::Revoked);

    let live = "sk-proj-9876543210abcdef9876543210abcdef9876";
    let res_live = KeyVerifier::verify_key(live);
    matches!(res_live.status, KeyStatus::Live);
    assert!(res_live.permissions.contains("Model Inference"));
}

#[test]
fn test_verify_stripe_modes() {
    let test_key = "sk_test_51MockTestingKey123456789";
    let res_test = KeyVerifier::verify_key(test_key);
    assert_eq!(res_test.key_type, "Stripe Secret Key");
    assert!(res_test.permissions.contains("Test Mode"));

    let live_key = "sk_mocklive_51MockLiveTestingKey987654321";
    let res_live = KeyVerifier::verify_key(live_key);
    assert!(res_live.permissions.contains("PRODUCTION Livemode"));
}

#[test]
fn test_verify_aws_tokens() {
    let mock_aws = "AKIAFAKETEST00000000";
    let res = KeyVerifier::verify_key(mock_aws);
    assert_eq!(res.key_type, "AWS IAM Access Key");
    matches!(res.status, KeyStatus::Revoked);
}
