use secretguard::shield::ScreenShield;
use secretguard::SecretGuardEngine;

#[test]
fn test_screen_shield_masking_behavior() {
    let engine = SecretGuardEngine::new();
    let sample_output = "API_KEY=sk-proj-1234567890abcdef1234567890abcdef1234567890";

    // Forced shield active (simulating meeting running)
    let masked = ScreenShield::mask_screen_line(sample_output, &engine, true);
    assert!(masked.contains("SCREEN-SHIELD BLURRED"));
    assert!(masked.contains("[REDACTED]"));
    assert!(!masked.contains("1234567890abcdef"));

    // Clean line should remain untampered even when meeting is active
    let clean_output = "Server running on port 3000";
    let clean_masked = ScreenShield::mask_screen_line(clean_output, &engine, true);
    assert_eq!(clean_masked, clean_output);
}
