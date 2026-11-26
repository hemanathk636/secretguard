mod common;

use secretguard::audit::{AuditIntegrityError, AuditLedger};
use secretguard::broker::{ApprovalToken, SecurityBroker};
use secretguard::identity::{IdentityContext, RequesterType, TrustTier};
use secretguard::policy::{
    AuthorizationDecision, OperationRequest, OperationType, PolicyEngine, PolicyRule,
};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

static P4_MUTEX: Mutex<()> = Mutex::new(());

fn setup_p4_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("sg_phase4_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &dir);
    dir
}

fn cleanup_p4_dir(dir: &PathBuf) {
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_policy_conflict_precedence_and_validation() {
    let engine = PolicyEngine {
        rules: vec![
            PolicyRule {
                id: "allow-get".to_string(),
                name: "Allow Get".to_string(),
                allowed_roles: vec![RequesterType::AutonomousAgent],
                min_trust_tier: TrustTier::Tier1Restricted,
                allowed_credentials: vec!["GITHUB_TOKEN".to_string()],
                allowed_repositories: vec!["*".to_string()],
                allowed_domains: vec!["api.github.com".to_string()],
                allowed_operations: vec!["GET".to_string(), "POST".to_string()],
                denied_operations: vec![],
                approval_required_for: vec![],
                delegate_only: true,
            },
            PolicyRule {
                id: "deny-get-approve-post".to_string(),
                name: "Deny Get and Require Approval for Post".to_string(),
                allowed_roles: vec![RequesterType::AutonomousAgent],
                min_trust_tier: TrustTier::Tier1Restricted,
                allowed_credentials: vec!["GITHUB_TOKEN".to_string()],
                allowed_repositories: vec!["*".to_string()],
                allowed_domains: vec!["api.github.com".to_string()],
                allowed_operations: vec!["POST".to_string()],
                denied_operations: vec!["GET".to_string()],
                approval_required_for: vec!["POST".to_string()],
                delegate_only: true,
            },
        ],
    };

    let val = engine.validate();
    assert!(val.valid);
    assert!(
        !val.warnings.is_empty(),
        "Cross-rule allow vs deny conflict should emit a validation warning"
    );

    let agent = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);

    // Deny MUST override earlier Allow
    let get_req = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/user",
    );
    let get_trace = engine.evaluate_with_explanation(&get_req);
    assert!(matches!(
        get_trace.decision,
        AuthorizationDecision::Deny { .. }
    ));
    assert_eq!(get_trace.denied_by, vec!["deny-get-approve-post"]);

    // RequireHumanApproval MUST override earlier Allow
    let post_req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/a/b/issues",
    );
    let post_trace = engine.evaluate_with_explanation(&post_req);
    assert!(matches!(
        post_trace.decision,
        AuthorizationDecision::RequireHumanApproval { .. }
    ));
}

#[test]
fn test_approval_binding_replay_and_expiration() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("approval");

    let broker = SecurityBroker::try_new().unwrap();
    let agent = IdentityContext::mock(
        "claude",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/org/repo/pulls",
    );

    // Without approval -> RequireHumanApproval
    let d0 = broker.authorize_with_approval(&req, None);
    assert!(matches!(
        d0,
        AuthorizationDecision::RequireHumanApproval { .. }
    ));

    // Issue challenge & approve
    let challenge = broker.approval_manager.issue_challenge(&req, Some(60));
    assert!(!challenge.prompt.contains("ghp_"));
    let token = broker
        .approval_manager
        .approve_challenge(&challenge)
        .unwrap();

    // First use succeeds
    let d1 = broker.authorize_with_approval(&req, Some(&token));
    assert_eq!(d1, AuthorizationDecision::AllowDelegated);

    // Replay of same token MUST be denied
    let d_replay = broker.authorize_with_approval(&req, Some(&token));
    assert!(matches!(d_replay, AuthorizationDecision::Deny { .. }));

    // Mismatched request MUST be denied
    let challenge2 = broker.approval_manager.issue_challenge(&req, Some(60));
    let token2 = broker
        .approval_manager
        .approve_challenge(&challenge2)
        .unwrap();
    let other_req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/org/other/pulls",
    );
    let d_mismatch = broker.authorize_with_approval(&other_req, Some(&token2));
    assert!(matches!(d_mismatch, AuthorizationDecision::Deny { .. }));

    // Expired token MUST be denied
    let expired = ApprovalToken {
        nonce: "deadbeef".to_string(),
        request_fingerprint: token2.request_fingerprint,
        expires_at_epoch_secs: 1,
        signature: String::new(),
    };
    let d_expired = broker.authorize_with_approval(&req, Some(&expired));
    assert!(matches!(d_expired, AuthorizationDecision::Deny { .. }));

    cleanup_p4_dir(&dir);
}

#[test]
fn test_audit_ledger_concurrent_writers_sanitization_and_tamper_detection() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("ledger");

    // Raw secret accidentally passed as credential_name must be redacted
    let raw_secret = format!("sk-proj-{}", "aB3dEf9GhIjK2LmNoPqRsTuVwXyZ012345");
    let mut handles = Vec::new();
    for i in 0..6 {
        let sec = raw_secret.clone();
        handles.push(std::thread::spawn(move || {
            let caller = IdentityContext::mock(
                "claude",
                RequesterType::AutonomousAgent,
                Some("org/repo"),
                None,
            );
            let gh_token = common::synth_github_token();
            let target_url = format!("https://api.github.com/user?token={}", gh_token);
            let req = OperationRequest::new(
                caller,
                if i == 0 { &sec } else { "GITHUB_TOKEN" },
                OperationType::HttpGet,
                &target_url,
            );
            AuditLedger::append_decision_atomic(&req, &AuthorizationDecision::AllowDelegated, None)
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let ledger = AuditLedger::load(None).unwrap();
    assert_eq!(ledger.records.len(), 6);
    assert_eq!(ledger.verify_integrity().unwrap(), 6);

    // Ensure zero secret leakage in persisted JSON
    let raw_json = fs::read_to_string(AuditLedger::get_default_path()).unwrap();
    assert!(!raw_json.contains("sk-proj-"));
    assert!(!raw_json.contains("ghp_123456"));

    // Wrong key detection
    let wrong_key = [0xAAu8; 32];
    assert!(matches!(
        ledger.verify_integrity_with_key(&wrong_key),
        Err(AuditIntegrityError::HashVerificationFailed { .. })
    ));

    // Timestamp regression detection
    let mut regressed = ledger.clone();
    regressed.records[1].timestamp_epoch_secs = 1;
    regressed.records[0].timestamp_epoch_secs = 9999999999;
    assert!(matches!(
        regressed.verify_integrity(),
        Err(AuditIntegrityError::HashVerificationFailed { .. })
    ));

    // Record deletion detection
    let mut deleted = ledger.clone();
    deleted.records.remove(0);
    assert!(matches!(
        deleted.verify_integrity(),
        Err(AuditIntegrityError::SequenceMismatch { .. })
    ));

    cleanup_p4_dir(&dir);
}

#[test]
fn test_phase4_cli_policy_and_audit_commands() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("cli");
    let bin = env!("CARGO_BIN_EXE_secretguard");

    let val = Command::new(bin)
        .env("SECRETGUARD_DIR", &dir)
        .args(["policy", "validate"])
        .output()
        .unwrap();
    assert!(val.status.success());
    assert!(String::from_utf8_lossy(&val.stdout).contains("VALID"));

    let exp = Command::new(bin)
        .env("SECRETGUARD_DIR", &dir)
        .args(["policy", "explain", "GITHUB_TOKEN", "GET"])
        .output()
        .unwrap();
    assert!(exp.status.success());
    assert!(String::from_utf8_lossy(&exp.stdout).contains("Explanation:"));

    let aud = Command::new(bin)
        .env("SECRETGUARD_DIR", &dir)
        .args(["audit", "ledger", "verify"])
        .output()
        .unwrap();
    assert!(aud.status.success());

    cleanup_p4_dir(&dir);
}

#[test]
fn test_forged_approval_token_cross_instance_replay_and_binary_hash_binding() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("adv_approval");

    let broker1 = SecurityBroker::try_new().unwrap();
    let mut agent = IdentityContext::mock(
        "claude",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    agent.binary_hash = Some("sha256:aaa111".to_string());

    let req = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/org/repo/pulls",
    );

    // 1. Forged token with self-computed SHA-256 fingerprint but invalid signature MUST be denied
    let forged = ApprovalToken {
        nonce: "forged-nonce-1234".to_string(),
        request_fingerprint: secretguard::broker::ApprovalManager::compute_request_fingerprint(
            &req,
        ),
        expires_at_epoch_secs: u64::MAX / 2,
        signature: "00".repeat(32),
    };
    let d_forged = broker1.authorize_with_approval(&req, Some(&forged));
    assert!(matches!(d_forged, AuthorizationDecision::Deny { .. }));

    // 2. Cross-instance replay: consumed in broker1, replayed in fresh broker2 MUST be denied
    let challenge = broker1.approval_manager.issue_challenge(&req, Some(60));
    let token = broker1
        .approval_manager
        .approve_challenge(&challenge)
        .unwrap();
    assert_eq!(
        broker1.authorize_with_approval(&req, Some(&token)),
        AuthorizationDecision::AllowDelegated
    );

    let broker2 = SecurityBroker::try_new().unwrap();
    let d_cross_replay = broker2.authorize_with_approval(&req, Some(&token));
    assert!(matches!(d_cross_replay, AuthorizationDecision::Deny { .. }));

    // 3. Binary hash mismatch MUST be denied
    let challenge2 = broker1.approval_manager.issue_challenge(&req, Some(60));
    let token2 = broker1
        .approval_manager
        .approve_challenge(&challenge2)
        .unwrap();
    let mut modified_agent = agent;
    modified_agent.binary_hash = Some("sha256:bbb222".to_string());
    let req_modified_bin = OperationRequest::new(
        modified_agent,
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/org/repo/pulls",
    );
    let d_bin_mismatch = broker1.authorize_with_approval(&req_modified_bin, Some(&token2));
    assert!(matches!(d_bin_mismatch, AuthorizationDecision::Deny { .. }));

    cleanup_p4_dir(&dir);
}

#[test]
fn test_audit_ledger_tail_truncation_rollback_and_missing_key() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("adv_ledger");

    let caller = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
    for i in 0..3 {
        let req = OperationRequest::new(
            caller.clone(),
            "GITHUB_TOKEN",
            OperationType::HttpGet,
            &format!("https://api.github.com/user/{}", i),
        );
        AuditLedger::append_decision_atomic(&req, &AuthorizationDecision::AllowDelegated, None)
            .unwrap();
    }

    let ledger = AuditLedger::load(None).unwrap();
    assert_eq!(ledger.records.len(), 3);

    // 1. Tail truncation (remove last record directly on disk without updating checkpoint)
    let mut truncated = ledger.clone();
    truncated.records.pop();
    fs::write(
        AuditLedger::get_default_path(),
        serde_json::to_vec_pretty(&truncated).unwrap(),
    )
    .unwrap();
    let err = AuditLedger::load(None).unwrap_err();
    assert!(
        err.contains("truncation") || err.contains("Truncation"),
        "Expected truncation error, got: {}",
        err
    );

    // 2. Full wipe to empty file MUST also be detected via audit_checkpoint.json
    fs::write(AuditLedger::get_default_path(), "").unwrap();
    let err_empty = AuditLedger::load(None).unwrap_err();
    assert!(
        err_empty.contains("empty") || err_empty.contains("Truncation"),
        "Expected empty/truncation error, got: {}",
        err_empty
    );

    // Restore valid ledger for missing-key test
    fs::write(
        AuditLedger::get_default_path(),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();
    let key_path = AuditLedger::get_default_path()
        .parent()
        .unwrap()
        .join("audit.hmac.key");
    assert!(
        key_path.exists(),
        "audit.hmac.key must exist in SECRETGUARD_DIR"
    );
    fs::remove_file(&key_path).unwrap();
    let key_res = secretguard::audit::get_or_create_audit_key();
    assert!(
        key_res.is_err(),
        "Deleting audit.hmac.key while audit_ledger.json exists must fail closed"
    );

    cleanup_p4_dir(&dir);
}

#[test]
fn test_vault_run_blocks_quarantined_secondary_key() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("adv_vaultrun");
    let bin = env!("CARGO_BIN_EXE_secretguard");

    let out = Command::new(bin)
        .env("SECRETGUARD_DIR", &dir)
        .args([
            "vault",
            "run",
            "SAFE_KEY",
            "QUARANTINED_SECRET",
            "--",
            "echo",
            "should-not-run",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "vault run must block QUARANTINED_SECRET even as a secondary key"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Security Violation") || stderr.contains("Quarantined"),
        "Expected security violation in stderr, got: {}",
        stderr
    );

    cleanup_p4_dir(&dir);
}

#[test]
fn test_approval_cross_process_persistence_and_fail_closed_without_key() {
    // Child-process entrypoint for real cross-process approval verification
    if let Ok(role) = std::env::var("SG_CHILD_APPROVAL_ROLE") {
        let dir = PathBuf::from(std::env::var("SECRETGUARD_DIR").unwrap());
        let token_file = dir.join("cross_proc_token.json");
        let mut agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("org/repo"),
            None,
        );
        agent.pid = 42424;
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpPost,
            "https://api.github.com/repos/org/repo/pulls",
        );
        let broker = SecurityBroker::try_new().unwrap();
        if role == "issue" {
            let ch = broker.approval_manager.issue_challenge(&req, Some(120));
            let tok = broker.approval_manager.approve_challenge(&ch).unwrap();
            fs::write(&token_file, serde_json::to_vec(&tok).unwrap()).unwrap();
            return;
        } else if role == "consume" {
            let tok: ApprovalToken =
                serde_json::from_slice(&fs::read(&token_file).unwrap()).unwrap();
            let d = broker.authorize_with_approval(&req, Some(&tok));
            assert_eq!(d, AuthorizationDecision::AllowDelegated);
            return;
        } else if role == "replay" {
            let tok: ApprovalToken =
                serde_json::from_slice(&fs::read(&token_file).unwrap()).unwrap();
            let d = broker.authorize_with_approval(&req, Some(&tok));
            assert!(matches!(d, AuthorizationDecision::Deny { .. }));
            return;
        }
    }

    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("cross_proc_approval");
    let exe = std::env::current_exe().unwrap();

    // 1. Process 1 issues & signs token (with no pre-existing vault.enc)
    let out1 = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_APPROVAL_ROLE", "issue")
        .args([
            "--exact",
            "test_approval_cross_process_persistence_and_fail_closed_without_key",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out1.status.success(),
        "Process 1 failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // 2. Process 2 consumes & verifies token using persistent vault.key
    let out2 = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_APPROVAL_ROLE", "consume")
        .args([
            "--exact",
            "test_approval_cross_process_persistence_and_fail_closed_without_key",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "Process 2 failed to consume token across processes: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    // 3. Process 3 replays same token -> MUST be denied via persistent approval_nonces.json
    let out3 = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_APPROVAL_ROLE", "replay")
        .args([
            "--exact",
            "test_approval_cross_process_persistence_and_fail_closed_without_key",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out3.status.success(),
        "Process 3 replay check failed: {}",
        String::from_utf8_lossy(&out3.stderr)
    );

    // 4. Corrupt .master.key -> approve_challenge MUST fail closed (no silent ephemeral fallback)
    let master_key_path = secretguard::vault::get_master_key_path().unwrap();
    assert!(master_key_path.exists());
    fs::write(&master_key_path, b"corrupt").unwrap();
    let broker = SecurityBroker::try_new().unwrap();
    let agent = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/org/repo/pulls",
    );
    let ch = broker.approval_manager.issue_challenge(&req, Some(60));
    assert!(
        broker.approval_manager.approve_challenge(&ch).is_err(),
        "Corrupted persistent key must fail closed instead of falling back to an ephemeral key"
    );

    cleanup_p4_dir(&dir);
}

#[test]
fn test_audit_checkpoint_crash_consistency_and_edge_cases() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("cp_crash");

    let caller = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
    for i in 0..2 {
        let req = OperationRequest::new(
            caller.clone(),
            "GITHUB_TOKEN",
            OperationType::HttpGet,
            &format!("https://api.github.com/user/{}", i),
        );
        AuditLedger::append_decision_atomic(&req, &AuthorizationDecision::AllowDelegated, None)
            .unwrap();
    }
    let ledger_path = AuditLedger::get_default_path();
    let cp_path = secretguard::audit::AuditCheckpoint::path_for(&ledger_path);
    let snapshot_2_ledger = fs::read(&ledger_path).unwrap();
    let snapshot_2_cp = fs::read(&cp_path).unwrap();

    // Append 3rd record
    let req3 = OperationRequest::new(
        caller,
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/user/2",
    );
    AuditLedger::append_decision_atomic(&req3, &AuthorizationDecision::AllowDelegated, None)
        .unwrap();
    let snapshot_3_ledger = fs::read(&ledger_path).unwrap();
    let snapshot_3_cp = fs::read(&cp_path).unwrap();

    // Case 1: Crash after ledger persistence (seq 3) but before checkpoint persistence (seq 2)
    // Strict forward extension of valid checkpoint -> loads cleanly
    fs::write(&ledger_path, &snapshot_3_ledger).unwrap();
    fs::write(&cp_path, &snapshot_2_cp).unwrap();
    let recovered = AuditLedger::load(None).unwrap();
    assert_eq!(recovered.records.len(), 3);

    // Case 2: Crash after checkpoint persistence (seq 3) before ledger persistence (seq 2)
    // OR restoration of older valid snapshot -> MUST fail closed
    fs::write(&ledger_path, &snapshot_2_ledger).unwrap();
    fs::write(&cp_path, &snapshot_3_cp).unwrap();
    assert!(AuditLedger::load(None).is_err());

    // Case 3: Missing checkpoint with non-empty ledger -> MUST fail closed
    fs::write(&ledger_path, &snapshot_3_ledger).unwrap();
    fs::remove_file(&cp_path).unwrap();
    assert!(AuditLedger::load(None).is_err());

    // Case 4: Missing ledger with existing checkpoint -> MUST fail closed
    fs::remove_file(&ledger_path).unwrap();
    fs::write(&cp_path, &snapshot_3_cp).unwrap();
    assert!(AuditLedger::load(None).is_err());

    // Case 5: Deletion of both ledger and checkpoint -> returns empty ledger (local trust boundary)
    fs::remove_file(&cp_path).unwrap();
    let empty = AuditLedger::load(None).unwrap();
    assert!(empty.records.is_empty());

    cleanup_p4_dir(&dir);
}

#[test]
fn test_audit_key_isolation_across_secretguard_dir_switches() {
    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir_a = setup_p4_dir("key_iso_a");
    let key_a = secretguard::audit::get_or_create_audit_key().unwrap();
    let caller = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
    let req = OperationRequest::new(
        caller,
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/user",
    );
    AuditLedger::append_decision_atomic(&req, &AuthorizationDecision::AllowDelegated, None)
        .unwrap();

    // Switch SECRETGUARD_DIR in the exact same process
    let dir_b = setup_p4_dir("key_iso_b");
    let key_b = secretguard::audit::get_or_create_audit_key().unwrap();
    assert_ne!(
        key_a, key_b,
        "Cached key from directory A must never be reused for directory B"
    );
    AuditLedger::append_decision_atomic(&req, &AuthorizationDecision::AllowDelegated, None)
        .unwrap();
    assert_eq!(AuditLedger::load(None).unwrap().records.len(), 1);

    // Switch back to directory A and verify its ledger still verifies with its own key
    std::env::set_var("SECRETGUARD_DIR", &dir_a);
    assert_eq!(AuditLedger::load(None).unwrap().records.len(), 1);

    cleanup_p4_dir(&dir_a);
    cleanup_p4_dir(&dir_b);
}

#[test]
fn test_kernel_lock_multiprocess_hold_pause_unexpected_exit_and_reopen_domain() {
    if let Ok(role) = std::env::var("SG_CHILD_KLOCK_ROLE") {
        let dir = PathBuf::from(std::env::var("SECRETGUARD_DIR").unwrap());
        if role == "hold_pause_exit" {
            let _lock = secretguard::audit::AuditKernelLock::acquire_exclusive(&dir).unwrap();
            fs::write(dir.join("lock_held.flag"), "1").unwrap();
            let release_flag = dir.join("release_child.flag");
            while !release_flag.exists() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Terminate unexpectedly without dropping _lock
            std::process::exit(1);
        } else if role == "try_blocked" {
            // Reopening .audit_ledger.lock in another OS process must share the same kernel lock domain
            assert!(
                secretguard::audit::AuditKernelLock::try_acquire_exclusive(&dir)
                    .unwrap()
                    .is_none(),
                "Process B must NOT enter while Process A holds kernel lock"
            );
            assert!(
                secretguard::audit::AuditKernelLock::try_acquire_shared(&dir)
                    .unwrap()
                    .is_none(),
                "Shared verifier must NOT enter while Process A holds exclusive kernel lock"
            );
            return;
        } else if role == "try_after_exit" {
            let _lock = secretguard::audit::AuditKernelLock::try_acquire_exclusive(&dir)
                .unwrap()
                .expect("Process B must acquire kernel lock after Process A exits unexpectedly");
            return;
        }
    }

    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("klock_mp");
    let exe = std::env::current_exe().unwrap();

    // 1. Spawn Process A to acquire the persistent kernel lock and pause
    let mut child_a = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_KLOCK_ROLE", "hold_pause_exit")
        .args([
            "--exact",
            "test_kernel_lock_multiprocess_hold_pause_unexpected_exit_and_reopen_domain",
            "--nocapture",
        ])
        .spawn()
        .unwrap();

    let held_flag = dir.join("lock_held.flag");
    for _ in 0..200 {
        if held_flag.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    assert!(held_flag.exists(), "Process A failed to acquire lock");

    // 2. Spawn Process B while Process A is paused -> cannot enter & reopening lock does not bypass
    let out_b1 = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_KLOCK_ROLE", "try_blocked")
        .args([
            "--exact",
            "test_kernel_lock_multiprocess_hold_pause_unexpected_exit_and_reopen_domain",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out_b1.status.success(),
        "Process B blocked check failed: {}",
        String::from_utf8_lossy(&out_b1.stderr)
    );

    // 3. Signal Process A to exit unexpectedly without unlocking
    fs::write(dir.join("release_child.flag"), "1").unwrap();
    let status_a = child_a.wait().unwrap();
    assert!(!status_a.success());

    // 4. Process B immediately acquires the kernel-released lock; persistent .audit_ledger.lock remains
    let out_b2 = Command::new(&exe)
        .env("SECRETGUARD_DIR", &dir)
        .env("SG_CHILD_KLOCK_ROLE", "try_after_exit")
        .args([
            "--exact",
            "test_kernel_lock_multiprocess_hold_pause_unexpected_exit_and_reopen_domain",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out_b2.status.success(),
        "Process B failed after Process A exited: {}",
        String::from_utf8_lossy(&out_b2.stderr)
    );
    assert!(
        dir.join(".audit_ledger.lock").exists(),
        "Persistent .audit_ledger.lock must never be deleted during normal operation"
    );

    cleanup_p4_dir(&dir);
}

#[test]
fn test_kernel_lock_multiprocess_concurrent_appenders_and_verifiers() {
    if let Ok(role) = std::env::var("SG_CHILD_MP_ROLE") {
        let dir = PathBuf::from(std::env::var("SECRETGUARD_DIR").unwrap());
        let start_flag = dir.join("start.flag");
        while !start_flag.exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        if role == "append" {
            let caller =
                IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
            for i in 0..3 {
                let req = OperationRequest::new(
                    caller.clone(),
                    "GITHUB_TOKEN",
                    OperationType::HttpGet,
                    &format!("https://api.github.com/mp/{}/{}", std::process::id(), i),
                );
                AuditLedger::append_decision_atomic(
                    &req,
                    &AuthorizationDecision::AllowDelegated,
                    None,
                )
                .unwrap();
            }
            return;
        } else if role == "verify" {
            for _ in 0..3 {
                let ledger = AuditLedger::load(None).unwrap();
                if !ledger.records.is_empty() {
                    ledger.verify_integrity().unwrap();
                }
            }
            return;
        }
    }

    let _guard = P4_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_p4_dir("klock_mp_append");
    let exe = std::env::current_exe().unwrap();

    // Pre-initialize audit.hmac.key before spawning concurrent child processes
    let _ = secretguard::audit::get_or_create_audit_key().unwrap();

    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            Command::new(&exe)
                .env("SECRETGUARD_DIR", &dir)
                .env("SG_CHILD_MP_ROLE", "append")
                .args([
                    "--exact",
                    "test_kernel_lock_multiprocess_concurrent_appenders_and_verifiers",
                    "--nocapture",
                ])
                .spawn()
                .unwrap(),
        );
    }
    for _ in 0..2 {
        children.push(
            Command::new(&exe)
                .env("SECRETGUARD_DIR", &dir)
                .env("SG_CHILD_MP_ROLE", "verify")
                .args([
                    "--exact",
                    "test_kernel_lock_multiprocess_concurrent_appenders_and_verifiers",
                    "--nocapture",
                ])
                .spawn()
                .unwrap(),
        );
    }

    // Release all 6 OS processes simultaneously
    fs::write(dir.join("start.flag"), "1").unwrap();

    for mut c in children {
        let st = c.wait().unwrap();
        assert!(st.success(), "Concurrent child process failed");
    }

    let ledger = AuditLedger::load(None).unwrap();
    assert_eq!(ledger.records.len(), 12);
    assert_eq!(ledger.verify_integrity().unwrap(), 12);
    assert!(dir.join(".audit_ledger.lock").exists());

    cleanup_p4_dir(&dir);
}
