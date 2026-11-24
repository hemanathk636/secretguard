use secretguard::ghost::GhostVirtualizer;
use secretguard::immune::ImmuneEngine;
use secretguard::timemachine::TimeMachine;
use secretguard::SecretGuardEngine;
use std::fs;
use std::process::Command;
use std::sync::Mutex;

static ADV_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_ghost_session_aes_256_gcm_encryption() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_ghost_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let secret = "sk-proj-superSecretRealKey1234567890abcdef12345678";

    let mut session = GhostVirtualizer::load_session();
    session
        .mappings
        .insert("sk-ghost-test".to_string(), secret.to_string());
    if let Err(e) = GhostVirtualizer::save_session(&session) {
        panic!("Save session failed with error: {:?}", e);
    }

    let session_path = GhostVirtualizer::get_session_path();
    assert!(session_path.exists());
    assert_eq!(
        session_path.extension().and_then(|s| s.to_str()),
        Some("enc")
    );

    // 3. Verify on-disk bytes are ciphertext, NOT plaintext
    let raw_bytes = fs::read(&session_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_str.contains(secret),
        "CRITICAL: Plaintext secret found in session file!"
    );
    assert!(
        serde_json::from_slice::<serde_json::Value>(&raw_bytes).is_err(),
        "Session file should be encrypted binary, not plain JSON"
    );

    // 4. Verify decryption round-trip via vault key
    let loaded = GhostVirtualizer::load_session();
    assert!(!loaded.mappings.is_empty());

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_genuine_provider_revocation_classification() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_prov_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let engine = SecretGuardEngine::new();

    let github_token = "ghp_1234567890abcdef1234567890abcdef1234";
    let report_gh = ImmuneEngine::trigger_containment(github_token, &engine)
        .expect("GitHub token containment should succeed");
    assert_eq!(report_gh.provider, "GitHub Personal Access Token");
    assert!(report_gh
        .direct_rotation_url
        .contains("github.com/settings/tokens"));

    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    let report_aws = ImmuneEngine::trigger_containment(aws_key, &engine)
        .expect("AWS key containment should succeed");
    assert_eq!(report_aws.provider, "AWS IAM Access Key");
    assert!(report_aws
        .direct_rotation_url
        .contains("console.aws.amazon.com"));

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_deep_git_history_scrubbing_across_all_commits() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_git_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    fs::write(
        temp_dir.join("app.rs"),
        "fn main() { println!(\"Hello\"); }",
    )
    .unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "Commit 1: Initial clean commit"]);

    // Commit 2: Leaked OpenAI credential
    let leaked_key = "sk-proj-leakedTokenInHistory1234567890abcdef";
    fs::write(
        temp_dir.join("config.env"),
        format!("OPENAI_KEY=\"{}\"\n", leaked_key),
    )
    .unwrap();
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
    assert_eq!(
        scan_report.tainted_commits[0].summary,
        "Commit 2: Accidental leak in history"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_csprng_master_key_generation() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_master_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let key1 = secretguard::vault::get_or_generate_master_key()
        .expect("Failed to get or generate master key");
    assert_eq!(key1.len(), 32);
    // Verify non-zero entropy
    assert!(key1.iter().any(|&b| b != 0));

    let key2 = secretguard::vault::get_or_generate_master_key().expect("Failed to get master key");
    assert_eq!(
        key1, key2,
        "Master key must be deterministically persisted on disk"
    );

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
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
    assert_ne!(
        okm1, okm_diff_info,
        "Different info must yield distinct expanded keys"
    );
}

#[test]
fn test_encoded_secret_base64_detection() {
    let engine = SecretGuardEngine::new();

    // Base64 of: sk-proj-1234567890abcdef1234567890abcdef
    // is: c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==
    let cmd = "export TOKEN=c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZg==";
    let res = engine.scan_and_sanitize(cmd);

    assert!(
        res.has_secret,
        "Engine must detect Base64-encoded secret token"
    );
    assert!(res.matched_rules.iter().any(|r| r.contains("Encoded")));
    assert!(res.sanitized_text.contains("[REDACTED"));
}

#[test]
fn test_adversarial_spoofed_pid_rejection() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_adv_pid_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let server = secretguard::ipc::IpcServer::new();
    let token = server.expected_token.clone();

    // Adversary claims to be 'claude-code' but sends a spoofed PID that does not exist
    let spoofed_msg = secretguard::ipc::IpcMessage::Authenticate {
        token,
        client_name: "claude-code".to_string(),
        pid: 9_999_999, // Non-existent process
    };

    let resp = server.handle_message_with_peer(&spoofed_msg, Some(9_999_999));
    match resp {
        secretguard::ipc::IpcMessage::AuthenticateResponse {
            authenticated,
            message,
            ..
        } => {
            assert!(!authenticated, "Server must reject spoofed PID");
            assert!(
                message.contains("Kernel process verification failed")
                    || message.contains("Security Violation"),
                "Expected kernel failure message, got '{}'",
                message
            );
        }
        _ => panic!("Expected AuthenticateResponse"),
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_ssrf_and_dns_rebinding_defense() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_ssrf_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "adversary-agent",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );

    let malicious_targets = [
        (
            "http://169.254.169.254/latest/meta-data/",
            "AWS/Azure Metadata",
        ),
        (
            "http://169.254.170.2/v2/credentials/",
            "AWS ECS Task Metadata",
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP Metadata",
        ),
        (
            "http://[fd00:ec2::254]/latest/meta-data/",
            "AWS IPv6 Metadata",
        ),
        ("https://10.0.0.1/admin", "RFC1918 Private 10.0.0.0/8"),
        (
            "https://172.16.0.1/internal",
            "RFC1918 Private 172.16.0.0/12",
        ),
        (
            "https://192.168.1.1/router",
            "RFC1918 Private 192.168.0.0/16",
        ),
        (
            "https://100.64.0.1/service",
            "Carrier-Grade NAT 100.64.0.0/10",
        ),
    ];

    for (target_url, desc) in malicious_targets {
        let req = secretguard::policy::OperationRequest::new(
            agent.clone(),
            "TEST_KEY",
            secretguard::policy::OperationType::HttpGet,
            target_url,
        );

        let err = broker
            .execute_delegated_call(&req, Some("mock-secret"))
            .expect_err(&format!(
                "Target '{}' ({}) must be blocked by SSRF defense",
                target_url, desc
            ));

        assert!(
            err.contains("SSRF")
                || err.contains("private/restricted")
                || err.contains("Cloud Metadata"),
            "Expected SSRF error for '{}', got: {}",
            target_url,
            err
        );
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_peer_pid_mismatch_rejection() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_adv_peer_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let server = secretguard::ipc::IpcServer::new();
    let token = server.expected_token.clone();

    // Adversary attempts to authenticate claiming PID 1000, but kernel reports peer PID 2000
    let msg = secretguard::ipc::IpcMessage::Authenticate {
        token,
        client_name: "claude-code".to_string(),
        pid: 1000,
    };

    let resp = server.handle_message_with_peer(&msg, Some(2000));
    match resp {
        secretguard::ipc::IpcMessage::AuthenticateResponse {
            authenticated,
            message,
            ..
        } => {
            assert!(
                !authenticated,
                "Server must reject when claimed PID mismatches kernel peer PID"
            );
            assert!(
                message.contains("PID spoofing detected"),
                "Expected PID spoofing message, got: {}",
                message
            );
        }
        _ => panic!("Expected AuthenticateResponse"),
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_header_injection_rejection() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_hdr_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "claude",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = secretguard::policy::OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        secretguard::policy::OperationType::HttpGet,
        "test://api.github.com/repos/org/repo/pulls",
    );

    // Injection payload containing CR/LF to attempt header splitting or curl config injection
    let malicious_secret = "ghp_validTokenPrefix\r\nheader = \"X-Injected-Header: pwned\"";
    let res = broker.execute_delegated_call(&req, Some(malicious_secret));
    assert!(
        res.is_err(),
        "Broker must reject secrets containing CR/LF header injection attempts"
    );
    let err = res.err().unwrap();
    assert!(
        err.contains("Header Injection Prevention") || err.contains("newline"),
        "Expected header injection error, got: {}",
        err
    );

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_ambiguous_ip_rejection() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_amb_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "agent",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );

    let ambiguous_ips = [
        "https://0x7f000001/admin",
        "https://0177.0.0.1/admin",
        "https://2130706433/admin",
    ];

    for url in ambiguous_ips {
        let req = secretguard::policy::OperationRequest::new(
            agent.clone(),
            "TEST_KEY",
            secretguard::policy::OperationType::HttpGet,
            url,
        );
        let err = broker
            .execute_delegated_call(&req, Some("mock-secret"))
            .expect_err(&format!("URL '{}' with ambiguous IP format must fail", url));
        assert!(
            err.contains("Ambiguous non-canonical IP") || err.contains("SSRF"),
            "Expected ambiguous IP error for '{}', got: {}",
            url,
            err
        );
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_fake_secretguard_hash_verification() {
    use std::collections::HashMap;
    let hints = HashMap::new();

    // Adversary launches a process named secretguard.exe with wrong hash and no TTY
    let (req_type, tier, score) = secretguard::identity::classify_requester_with_hash(
        "secretguard.exe",
        Some("untrusted_fake_sha256_hash_value"),
        &[],
        false,
        &hints,
    );

    assert_eq!(
        req_type,
        secretguard::identity::RequesterType::UnknownProcess,
        "Fake secretguard binary must not receive privileged human identity"
    );
    assert_eq!(
        tier,
        secretguard::identity::TrustTier::Tier0Blocked,
        "Fake secretguard binary must be assigned Tier0Blocked"
    );
    assert_eq!(
        score, 0,
        "Fake secretguard binary must receive zero trust score"
    );
}

#[test]
fn test_adversarial_non_tty_secretguard_restricted_tier() {
    use std::collections::HashMap;
    let hints = HashMap::new();
    let current_hash = secretguard::identity::IdentityContext::get_current_binary_hash();

    // 1. Non-TTY execution (e.g. background script, CI, daemon, pipe)
    let (req_type, tier, score) = secretguard::identity::classify_requester_with_hash(
        "secretguard",
        current_hash.as_deref(),
        &[],
        false, // NO TTY
        &hints,
    );

    assert_eq!(
        req_type,
        secretguard::identity::RequesterType::BuildOrScript,
        "Non-TTY secretguard execution must not be granted HumanInteractive status"
    );
    assert_eq!(
        tier,
        secretguard::identity::TrustTier::Tier1Restricted,
        "Non-TTY secretguard execution must be restricted to Tier1Restricted"
    );
    assert_eq!(score, 50);

    // 2. Interactive TTY execution
    let (req_type_tty, tier_tty, score_tty) = secretguard::identity::classify_requester_with_hash(
        "secretguard",
        current_hash.as_deref(),
        &[],
        true, // WITH interactive TTY
        &hints,
    );

    assert_eq!(
        req_type_tty,
        secretguard::identity::RequesterType::HumanInteractive,
        "Interactive TTY secretguard must be recognized as HumanInteractive"
    );
    assert_eq!(
        tier_tty,
        secretguard::identity::TrustTier::Tier3Privileged,
        "Interactive TTY secretguard receives Tier3Privileged"
    );
    assert_eq!(score_tty, 90);
}

#[test]
fn test_adversarial_subdomain_spoofing_loopback_rejected() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_sub_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "agent",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );

    // Attack: Craft URL with 127.0.0.1 prefix as subdomain on attacker host
    let spoofed_urls = [
        "http://127.0.0.1.attacker.example/steal",
        "http://127.0.0.1.local.attacker.example/steal",
        "http://localhost.attacker.example/steal",
    ];

    for url in spoofed_urls {
        let req = secretguard::policy::OperationRequest::new(
            agent.clone(),
            "GITHUB_TOKEN",
            secretguard::policy::OperationType::HttpGet,
            url,
        );
        let res = broker.execute_delegated_call(&req, Some("ghp_validToken"));
        assert!(
            res.is_err(),
            "Broker must reject spoofed loopback subdomains over HTTP: {}",
            url
        );
        let err = res.err().unwrap();
        assert!(
            err.contains("Invalid Protocol") || err.contains("SSRF"),
            "Expected protocol or SSRF rejection for '{}', got: {}",
            url,
            err
        );
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_github_repo_binding_and_policy_enforcement() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_repo_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "claude-code",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("company/secure-repo"),
        None,
    );

    // 1. Automatic repository binding from URL
    let read_req = secretguard::policy::OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        secretguard::policy::OperationType::HttpGet,
        "https://api.github.com/repos/company/secure-repo/pulls",
    );
    assert_eq!(
        read_req.repository.as_deref(),
        Some("company/secure-repo"),
        "Repository must be automatically parsed and bound from GitHub URL"
    );

    // GET operation is allowed delegated
    let read_decision = broker.authorize(&read_req);
    assert_eq!(
        read_decision,
        secretguard::policy::AuthorizationDecision::AllowDelegated
    );

    // 2. POST operation on repository requires interactive human approval
    let write_req = secretguard::policy::OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        secretguard::policy::OperationType::HttpPost,
        "https://api.github.com/repos/company/secure-repo/issues",
    );
    let write_decision = broker.authorize(&write_req);
    assert!(
        matches!(
            write_decision,
            secretguard::policy::AuthorizationDecision::RequireHumanApproval { .. }
        ),
        "POST operation by AI agent must require human approval"
    );

    // 3. DELETE operation is explicitly forbidden
    let delete_req = secretguard::policy::OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        secretguard::policy::OperationType::HttpDelete,
        "https://api.github.com/repos/company/secure-repo",
    );
    let delete_decision = broker.authorize(&delete_req);
    assert!(
        matches!(
            delete_decision,
            secretguard::policy::AuthorizationDecision::Deny { .. }
        ),
        "DELETE operation by AI agent must be denied by zero-trust policy"
    );

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_immune_local_quarantine_before_upstream() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_adv_immune_local_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let engine = secretguard::SecretGuardEngine::new();

    // Store a test credential in the vault
    let mut store = secretguard::vault::VaultStore::default();
    let exposed_token = "xoxb-mock-immune-test-quarantined-key";
    store
        .secrets
        .insert("SLACK_BOT_TOKEN".to_string(), exposed_token.to_string());
    secretguard::vault::save_vault(&store, None).expect("Vault must save test credential");

    // Trigger containment
    let report = secretguard::immune::ImmuneEngine::trigger_containment(exposed_token, &engine)
        .expect("Containment must succeed");
    assert_eq!(report.provider, "Slack Bot Token");

    // Verify local vault is immediately quarantined
    let loaded_vault = secretguard::vault::load_vault(None).expect("Vault must load");
    let quarantined_val = loaded_vault.secrets.get("SLACK_BOT_TOKEN").unwrap();
    assert!(
        quarantined_val.starts_with("[QUARANTINED_BLOCKED:"),
        "Local vault must have quarantined token immediately"
    );

    // Verify LifecycleManager state is quarantined
    let lm = secretguard::lifecycle::LifecycleManager::load(None).expect("LifecycleManager loads");
    let rec = lm.find_by_name("Slack Bot Token");
    assert!(rec.is_some(), "Credential record must be registered");
    assert!(
        matches!(
            rec.unwrap().state,
            secretguard::lifecycle::CredentialState::Quarantined { .. }
        ),
        "Lifecycle state must be Quarantined"
    );

    // Verify broker blocks quarantined token
    let broker = secretguard::broker::SecurityBroker::new();
    let agent = secretguard::identity::IdentityContext::mock(
        "agent",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = secretguard::policy::OperationRequest::new(
        agent,
        "QUARANTINED_Slack_Bot_Token",
        secretguard::policy::OperationType::HttpGet,
        "https://slack.com/api/auth.test",
    );
    let res = broker.execute_delegated_call(&req, None);
    assert!(
        res.is_err(),
        "Quarantined credential must be blocked by broker"
    );
    assert!(
        res.err().unwrap().contains("QUARANTINED"),
        "Error must specify quarantined circuit-breaker"
    );

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_adversarial_userinfo_credential_exfiltration_rejected() {
    let _lock = ADV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Adversarial attack: using URL userinfo syntax to trick parser into authorizing api.github.com
    // while sending credentials to attacker.example
    let evil_url = "https://api.github.com:443@attacker.example/repos/owner/repo/issues";

    // 1. SSRF destination validator must strictly reject userinfo '@'
    let dest_res = secretguard::broker::validate_url_and_destination(evil_url);
    assert!(dest_res.is_err(), "URL with userinfo '@' must be rejected");
    let err = dest_res.unwrap_err();
    assert!(
        err.contains("user information ('@')"),
        "Unexpected error message: '{}'",
        err
    );

    // 2. Policy engine domain extractor must fail closed and refuse domain match
    let agent = secretguard::identity::IdentityContext::mock(
        "claude-code",
        secretguard::identity::RequesterType::AutonomousAgent,
        Some("owner/repo"),
        None,
    );
    let req = secretguard::policy::OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        secretguard::policy::OperationType::HttpGet,
        evil_url,
    );
    assert!(
        req.target_domain.is_none(),
        "URL with userinfo must have target_domain = None"
    );

    let engine = secretguard::policy::PolicyEngine::default();
    let decision = engine.evaluate(&req);
    assert!(
        matches!(
            decision,
            secretguard::policy::AuthorizationDecision::Deny { .. }
        ),
        "Exfiltration URL must be denied by policy engine"
    );
}
