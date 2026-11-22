use secretguard::canary::CanaryManager;
use std::fs;

#[test]
fn test_canary_generation_formats() {
    let aws = CanaryManager::generate_canary("aws", "test");
    assert!(aws.token_value.starts_with("AKIA"));
    assert_eq!(aws.token_value.len(), 20);

    let ghp = CanaryManager::generate_canary("github", "test");
    assert!(ghp.token_value.starts_with("ghp_CANARY_"));

    let stripe = CanaryManager::generate_canary("stripe", "test");
    assert!(stripe.token_value.starts_with("sk_test_CANARY_"));
}

#[test]
fn test_plant_canary_tripwire() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_canary_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join(".env.example");
    let canary = CanaryManager::plant_canary(&target_file, "openai").expect("Planting failed");

    assert!(target_file.exists());
    let content = fs::read_to_string(&target_file).unwrap();
    assert!(content.contains(&canary.token_value));
    assert!(content.contains("OPENAI_API_KEY="));

    let _ = fs::remove_dir_all(&temp_dir);
}
