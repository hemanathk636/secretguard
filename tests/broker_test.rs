//! Integration tests for SecretGuard Local Security Broker & Authorization Architecture
//!
//! Verifies:
//! 1. Process identity classification & trust tier derivation
//! 2. Operation-aware policy evaluation (domain, method, and repository boundaries)
//! 3. Tamper-evident cryptographic audit ledger hash-chaining and persistence
//! 4. Audit ledger tamper detection and verification
//! 5. Broker delegated execution with secret scrubbing (zero raw token leakage)
//! 6. Full adversarial attack simulation suite execution

use secretguard::audit::{AuditIntegrityError, AuditLedger};
use secretguard::broker::SecurityBroker;
use secretguard::identity::{IdentityContext, RequesterType, TrustTier};
use secretguard::policy::{AuthorizationDecision, OperationRequest, OperationType, PolicyEngine};
use secretguard::self_test::run_security_self_test;
use std::fs;
use std::sync::Mutex;

static TEST_ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_process_identity_classification() {
    // 1. Current process should derive valid identity without panicking
    let current = IdentityContext::current();
    assert!(current.pid > 0);
    assert!(!current.executable_name.is_empty());
    assert!(current.trust_score <= 100);

    // 2. Mock Human Interactive should map to Privileged
    let human = IdentityContext::mock(
        "bash",
        RequesterType::HumanInteractive,
        Some("org/repo"),
        None,
    );
    assert_eq!(human.requester_type, RequesterType::HumanInteractive);
    assert_eq!(human.trust_tier, TrustTier::Tier3Privileged);
    assert!(human.trust_score >= 80);

    // 3. Mock Autonomous Agent (Claude Code) should map to StandardAgent
    let agent = IdentityContext::mock(
        "claude-code",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    assert_eq!(agent.requester_type, RequesterType::AutonomousAgent);
    assert_eq!(agent.trust_tier, TrustTier::Tier2StandardAgent);
    assert!(agent.trust_score >= 50 && agent.trust_score < 80);

    // 4. Mock Unknown Process should map to Tier0Blocked
    let unknown =
        IdentityContext::mock("unknown_payload", RequesterType::UnknownProcess, None, None);
    assert_eq!(unknown.requester_type, RequesterType::UnknownProcess);
    assert_eq!(unknown.trust_tier, TrustTier::Tier0Blocked);
    assert!(unknown.trust_score < 20);
}

#[test]
fn test_operation_aware_policy_matrix() {
    let engine = PolicyEngine::default();

    // Human interactive -> Allowed raw credential access
    let human = IdentityContext::mock(
        "zsh",
        RequesterType::HumanInteractive,
        Some("myorg/myrepo"),
        None,
    );
    let req_raw = OperationRequest::new(
        human.clone(),
        "GITHUB_TOKEN",
        OperationType::RawCredentialAccess,
        "https://api.github.com",
    );
    assert_eq!(engine.evaluate(&req_raw), AuthorizationDecision::AllowRaw);

    // AI agent -> Raw credential access is strictly DENIED
    let agent = IdentityContext::mock(
        "claude",
        RequesterType::AutonomousAgent,
        Some("myorg/myrepo"),
        None,
    );
    let req_agent_raw = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::RawCredentialAccess,
        "https://api.github.com",
    );
    assert!(matches!(
        engine.evaluate(&req_agent_raw),
        AuthorizationDecision::Deny { .. }
    ));

    // AI agent -> Delegated GET on approved domain -> AllowDelegated
    let req_agent_get = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/repos/myorg/myrepo/pulls",
    );
    assert_eq!(
        engine.evaluate(&req_agent_get),
        AuthorizationDecision::AllowDelegated
    );

    // AI agent -> POST on issues -> Requires human approval
    let req_agent_post = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpPost,
        "https://api.github.com/repos/myorg/myrepo/issues",
    );
    assert!(matches!(
        engine.evaluate(&req_agent_post),
        AuthorizationDecision::RequireHumanApproval { .. }
    ));

    // AI agent -> DELETE operation -> Strictly DENIED
    let req_agent_delete = OperationRequest::new(
        agent.clone(),
        "GITHUB_TOKEN",
        OperationType::HttpDelete,
        "https://api.github.com/repos/myorg/myrepo",
    );
    assert!(matches!(
        engine.evaluate(&req_agent_delete),
        AuthorizationDecision::Deny { .. }
    ));

    // Untrusted process -> Fail closed
    let rogue = IdentityContext::mock("infiltrator", RequesterType::UnknownProcess, None, None);
    let req_rogue = OperationRequest::new(
        rogue,
        "ANY_KEY",
        OperationType::HttpGet,
        "https://api.github.com",
    );
    assert!(matches!(
        engine.evaluate(&req_rogue),
        AuthorizationDecision::Deny { .. }
    ));
}

#[test]
fn test_tamper_evident_audit_ledger_lifecycle() {
    let temp_dir = std::env::temp_dir().join(format!("sg_broker_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let ledger_path = temp_dir.join("audit.ledger");

    let mut ledger = AuditLedger::new();
    assert_eq!(ledger.records.len(), 0);

    let ident = IdentityContext::mock("test-caller", RequesterType::ApprovedIde, None, None);
    let req1 = OperationRequest::new(
        ident.clone(),
        "OPENAI_API_KEY",
        OperationType::HttpPost,
        "https://api.openai.com/v1/chat/completions",
    );
    ledger.record_decision(&req1, &AuthorizationDecision::AllowDelegated);

    let req2 = OperationRequest::new(
        ident,
        "AWS_SECRET_ACCESS_KEY",
        OperationType::RawCredentialAccess,
        "https://s3.amazonaws.com",
    );
    ledger.record_decision(
        &req2,
        &AuthorizationDecision::Deny {
            reason: "IDE denied raw AWS credentials".to_string(),
        },
    );

    assert_eq!(ledger.records.len(), 2);
    assert_eq!(ledger.verify_integrity().unwrap(), 2);

    // Save ledger atomically to disk
    ledger.save(Some(&ledger_path)).expect("save ledger");
    assert!(ledger_path.exists());

    // Load ledger back from disk and verify cryptographic hash chain
    let loaded = AuditLedger::load(Some(&ledger_path)).expect("load ledger");
    assert_eq!(loaded.records.len(), 2);
    assert_eq!(loaded.verify_integrity().unwrap(), 2);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_audit_ledger_tamper_detection() {
    let mut ledger = AuditLedger::new();
    let ident = IdentityContext::mock(
        "worker",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );

    for i in 1..=5 {
        let req = OperationRequest::new(
            ident.clone(),
            &format!("KEY_{}", i),
            OperationType::HttpGet,
            "https://api.example.com",
        );
        ledger.record_decision(&req, &AuthorizationDecision::AllowDelegated);
    }

    assert_eq!(ledger.verify_integrity().unwrap(), 5);

    // Tamper with sequence #3's target_resource
    ledger.records[2].target_resource = "https://malicious-exfiltration.com".to_string();

    let err = ledger.verify_integrity().unwrap_err();
    match err {
        AuditIntegrityError::HashVerificationFailed { index, .. } => {
            assert_eq!(index, 2);
        }
        other => panic!(
            "Expected HashVerificationFailed at index 2, got {:?}",
            other
        ),
    }
}

#[test]
fn test_broker_delegated_execution_scrubs_secret() {
    let _guard = TEST_ENV_MUTEX.lock().unwrap();
    let broker = SecurityBroker::new();
    let agent = IdentityContext::mock(
        "claude-worker",
        RequesterType::AutonomousAgent,
        Some("company/project"),
        None,
    );
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/repos/company/project/commits",
    );

    let confidential_token = "ghp_MockSecretTokenValueForTestingDelegatedExecution987";
    let resp = broker
        .execute_delegated_call(&req, Some(confidential_token))
        .expect("delegated call should succeed");

    assert_eq!(resp.status_code, 200);
    let body_str = String::from_utf8(resp.body).expect("valid utf8");

    // The real token must NEVER appear anywhere in the body
    assert!(
        !body_str.contains(confidential_token),
        "Confidential token was leaked in response body!"
    );
    assert!(body_str.contains("delegated_execution"));
}

#[test]
fn test_security_self_test_all_simulations_pass() {
    let _guard = TEST_ENV_MUTEX.lock().unwrap();
    let report = run_security_self_test();
    assert_eq!(report.total, 6);
    assert_eq!(
        report.failed, 0,
        "Some adversarial attack simulations failed: {:?}",
        report.tests
    );
    assert!(report.is_all_passed());
}

#[test]
fn test_broker_quarantined_credential_blocked() {
    let _guard = TEST_ENV_MUTEX.lock().unwrap();
    let broker = SecurityBroker::new();
    let agent = IdentityContext::mock(
        "claude-worker",
        RequesterType::AutonomousAgent,
        Some("company/project"),
        None,
    );

    // 1. PolicyEngine directly denies QUARANTINED_ credentials
    let req_quarantined_name = OperationRequest::new(
        agent.clone(),
        "QUARANTINED_GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/repos/company/project",
    );
    let decision = broker
        .policy_engine
        .read()
        .unwrap()
        .evaluate(&req_quarantined_name);
    assert!(matches!(decision, AuthorizationDecision::Deny { .. }));

    // 2. Broker delegated execution strictly denies quarantined secrets
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/repos/company/project",
    );
    let quarantined_secret = "[QUARANTINED_BLOCKED:ghp_...7a9f]";
    let err = broker
        .execute_delegated_call(&req, Some(quarantined_secret))
        .unwrap_err();
    assert!(err.contains("QUARANTINED") || err.contains("Circuit-Breaker"));
}

#[test]
fn test_broker_ssrf_cloud_metadata_blocked() {
    let _guard = TEST_ENV_MUTEX.lock().unwrap();
    let broker = SecurityBroker::new();
    let agent = IdentityContext::mock(
        "claude-worker",
        RequesterType::AutonomousAgent,
        Some("company/project"),
        None,
    );

    // AWS/Azure metadata IP
    let req_aws = OperationRequest::new(
        agent.clone(),
        "AWS_KEY",
        OperationType::HttpGet,
        "http://169.254.169.254/latest/meta-data/",
    );
    let err_aws = broker
        .execute_delegated_call(&req_aws, Some("mock"))
        .unwrap_err();
    assert!(
        err_aws.contains("SSRF")
            || err_aws.contains("Metadata")
            || err_aws.contains("cloud metadata")
    );

    // GCP metadata domain
    let req_gcp = OperationRequest::new(
        agent,
        "GCP_KEY",
        OperationType::HttpGet,
        "http://metadata.google.internal/computeMetadata/v1/",
    );
    let err_gcp = broker
        .execute_delegated_call(&req_gcp, Some("mock"))
        .unwrap_err();
    assert!(
        err_gcp.contains("SSRF")
            || err_gcp.contains("Metadata")
            || err_gcp.contains("cloud metadata")
    );
}

#[test]
fn test_broker_fails_closed_on_corrupt_audit_ledger() {
    let _guard = TEST_ENV_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("sg_corrupt_ledger_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let ledger_path = temp_dir.join("audit_ledger.json");

    // Write a tampered/corrupt audit ledger
    let mut ledger = AuditLedger::new();
    let ident = IdentityContext::mock(
        "worker",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = OperationRequest::new(
        ident,
        "KEY",
        OperationType::HttpGet,
        "https://api.example.com",
    );
    ledger.record_decision(&req, &AuthorizationDecision::AllowDelegated);
    ledger.records[0].target_resource = "https://tampered.com".to_string(); // Corrupt hash chain
    ledger
        .save(Some(&ledger_path))
        .expect("save tampered ledger");

    // Temporarily set SECRETGUARD_DIR to the corrupted directory
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    // SecurityBroker::try_new() MUST fail closed and refuse to start
    let broker_res = SecurityBroker::try_new();
    assert!(
        broker_res.is_err(),
        "SecurityBroker must fail closed on tampered audit ledger"
    );

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}
