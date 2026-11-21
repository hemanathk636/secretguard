use secretguard::config::SecretGuardConfig;
use secretguard::SecretGuardEngine;

#[test]
fn test_config_template_generation() {
    let temp_dir = std::env::temp_dir().join(format!("sg_cfg_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cfg_path = temp_dir.join("secretguard.toml");

    assert!(SecretGuardConfig::generate_template(&cfg_path).is_ok());
    let content = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(content.contains("entropy_threshold"));
    assert!(content.contains("whitelist"));
    assert!(content.contains("[[custom_patterns]]"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_whitelist_suppression() {
    let engine = SecretGuardEngine::new();
    // Test that engine honors clean developer commands
    let clean = "git status && npm run build";
    let res = engine.scan_and_sanitize(clean);
    assert!(!res.has_secret);
}
