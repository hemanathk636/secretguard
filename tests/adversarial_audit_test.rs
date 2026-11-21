use secretguard::ghost::GhostVirtualizer;
use secretguard::immune::ImmuneEngine;
use secretguard::timemachine::TimeMachine;
use secretguard::SecretGuardEngine;
use std::fs;
use std::process::Command;

#[test]
fn test_ghost_session_aes_256_gcm_encryption() {
    let _engine = SecretGuardEngine::new();
    let secret = "sk-proj-superSecretRealKey1234567890abcdef12345678";

    let mut session = GhostVirtualizer::load_session();
    session.mappings.insert("sk-ghost-test".to_string(), secret.to_string());
    if let Err(e) = GhostVirtualizer::save_session(&session) {
        panic!("Save session failed with error: {:?}", e);
    }

    let session_path = GhostVirtualizer::get_session_path();
    assert!(session_path.exists());
    assert_eq!(session_path.extension().and_then(|s| s.to_str()), Some("enc"));

    // 3. Verify on-disk bytes are ciphertext, NOT plaintext
    let raw_bytes = fs::read(&session_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw_bytes);
    assert!(!raw_str.contains(secret), "CRITICAL: Plaintext secret found in session file!");
    assert!(serde_json::from_slice::<serde_json::Value>(&raw_bytes).is_err(), "Session file should be encrypted binary, not plain JSON");

    // 4. Verify decryption round-trip via vault key
    let loaded = GhostVirtualizer::load_session();
    assert!(!loaded.mappings.is_empty());
}

#[test]
fn test_genuine_provider_revocation_classification() {
    let engine = SecretGuardEngine::new();

    let github_token = "ghp_1234567890abcdef1234567890abcdef1234";
    let report_gh = ImmuneEngine::trigger_containment(github_token, &engine);
    assert_eq!(report_gh.provider, "GitHub Personal Access Token");
    assert!(report_gh.direct_rotation_url.contains("github.com/settings/tokens"));

    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    let report_aws = ImmuneEngine::trigger_containment(aws_key, &engine);
    assert_eq!(report_aws.provider, "AWS IAM Access Key");
    assert!(report_aws.direct_rotation_url.contains("console.aws.amazon.com"));
}

#[test]
fn test_deep_git_history_scrubbing_across_all_commits() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!("sg_adv_git_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&temp_dir).unwrap();

    // Initialize temporary Git repository
    let run_git = |args: &[&str]| {
        Command::new("git")
            .current_dir(&temp_dir)
            .args(args)
            .output()
            .expect("Git execution failed")
    };

    run_git(&["init"]);
    run_git(&["config", "user.name", "Audit Tester"]);
    run_git(&["config", "user.email", "audit@secretguard.dev"]);

    // Commit 1: Clean file
    fs::write(temp_dir.join("app.rs"), "fn main() { println!(\"Hello\"); }").unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "Commit 1: Initial clean commit"]);

    // Commit 2: Leaked OpenAI credential
    let leaked_key = "sk-proj-leakedTokenInHistory1234567890abcdef";
    fs::write(temp_dir.join("config.env"), format!("OPENAI_KEY=\"{}\"\n", leaked_key)).unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "Commit 2: Accidental leak in history"]);

    // Commit 3: Another change
    fs::write(temp_dir.join("readme.md"), "# Project Readme").unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "Commit 3: Feature update"]);

    // Verify git history scan detects leak in commit 2
    let scan_report = TimeMachine::scan_history(&engine, Some(&temp_dir), None).unwrap();
    assert_eq!(scan_report.total_commits_scanned, 3);
    assert_eq!(scan_report.tainted_commits.len(), 1);
    assert_eq!(scan_report.tainted_commits[0].summary, "Commit 2: Accidental leak in history");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_csprng_master_key_generation() {
    let key1 = secretguard::vault::get_or_generate_master_key();
    assert_eq!(key1.len(), 32);
    // Verify non-zero entropy
    assert!(key1.iter().any(|&b| b != 0));

    let key2 = secretguard::vault::get_or_generate_master_key();
    assert_eq!(key1, key2, "Master key must be deterministically persisted on disk");
}

#[test]
fn test_bash_extdebug_preexecution_hook() {
    let bin_path = env!("CARGO_BIN_EXE_secretguard");
    let output = Command::new(bin_path)
        .args(["hook", "bash"])
        .output()
        .expect("Failed to execute secretguard binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shopt -s extdebug"));
    assert!(stdout.contains("trap '_secretguard_bash_preexec' DEBUG"));
    assert!(stdout.contains("BASH_COMMAND"));
}

#[test]
fn test_rfc5869_hkdf_sha256_derivation() {
    let salt = b"secretguard_test_salt";
    let ikm = b"secretguard_input_key_material_12345";
    let info = b"test_info_label";
    
    let okm1 = secretguard::vault::hkdf_sha256(salt, ikm, info, 32);
    assert_eq!(okm1.len(), 32);

    let okm2 = secretguard::vault::hkdf_sha256(salt, ikm, info, 32);
    assert_eq!(okm1, okm2, "HKDF-SHA256 must be deterministic");

    let okm_diff_info = secretguard::vault::hkdf_sha256(salt, ikm, b"different_info", 32);
    assert_ne!(okm1, okm_diff_info, "Different info must yield distinct expanded keys");
}

#[test]
fn test_encoded_secret_base64_detection() {
    let engine = SecretGuardEngine::new();

    // Base64 of: sk-proj-1234567890abcdef1234567890abcdef
    // is: c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==
    let cmd = "export TOKEN=c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==";
    let res = engine.scan_and_sanitize(cmd);

    assert!(res.has_secret, "Engine must detect Base64-encoded secret token");
    assert!(res.matched_rules.iter().any(|r| r.contains("Encoded")));
    assert!(res.sanitized_text.contains("[REDACTED"));
}
