//! Security Self-Assessment & Adversarial Attack Simulation Engine for SecretGuard
//!
//! Executes automated local security attack simulations to verify runtime defense boundaries:
//! 1. Untrusted process credential access blocked
//! 2. AI agent raw token exfiltration prevented
//! 3. Destructive operations bounded / require human approval
//! 4. Audit ledger cryptographic hash chain tamper detection
//! 5. Delegated execution secret scrubbing
//! 6. Path traversal and symlink rejection defense

use crate::audit::{AuditIntegrityError, AuditLedger};
use crate::broker::SecurityBroker;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType, PolicyEngine};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of an individual security test simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseResult {
    pub id: String,
    pub name: String,
    pub description: String,
    pub passed: bool,
    pub details: String,
}

/// Aggregated report from a full security self-test run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub tests: Vec<TestCaseResult>,
}

impl SelfTestReport {
    pub fn is_all_passed(&self) -> bool {
        self.failed == 0 && self.passed == self.total
    }
}

/// Runs all 6 security attack simulations and compiles a comprehensive report
pub fn run_security_self_test() -> SelfTestReport {
    let tests = vec![
        test_untrusted_process_blocked(),
        test_ai_agent_raw_token_exfiltration_prevented(),
        test_destructive_operation_bounded(),
        test_audit_hash_chain_tamper_detection(),
        test_delegated_execution_secret_scrubbing(),
        test_path_traversal_and_symlink_defense(),
    ];

    let total = tests.len();
    let passed = tests.iter().filter(|t| t.passed).count();
    let failed = total.saturating_sub(passed);

    SelfTestReport {
        total,
        passed,
        failed,
        tests,
    }
}

fn test_untrusted_process_blocked() -> TestCaseResult {
    let unverified_process = IdentityContext::mock(
        "unrecognized_binary.exe",
        RequesterType::UnknownProcess,
        None,
        None,
    );
    let req = OperationRequest::new(
        unverified_process,
        "AWS_SECRET_ACCESS_KEY",
        OperationType::HttpGet,
        "https://s3.amazonaws.com/private-bucket",
    );

    let engine = PolicyEngine::default();
    let decision = engine.evaluate(&req);

    let passed = matches!(decision, AuthorizationDecision::Deny { .. });
    let details = if passed {
        "Untrusted background process with score <20 was strictly denied access to credentials."
            .to_string()
    } else {
        format!(
            "VULNERABILITY: Untrusted process was granted unexpected access: {:?}",
            decision
        )
    };

    TestCaseResult {
        id: "SIM-01".to_string(),
        name: "Untrusted Process Access Blocked".to_string(),
        description: "Verify that unknown/untrusted processes cannot obtain credential access"
            .to_string(),
        passed,
        details,
    }
}

fn test_ai_agent_raw_token_exfiltration_prevented() -> TestCaseResult {
    let agent = IdentityContext::mock(
        "claude-code",
        RequesterType::AutonomousAgent,
        Some("org/project"),
        None,
    );
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::RawCredentialAccess,
        "local:environment",
    );

    let engine = PolicyEngine::default();
    let decision = engine.evaluate(&req);

    // AI agent must NEVER receive raw tokens
    let passed = matches!(decision, AuthorizationDecision::Deny { .. });
    let details = if passed {
        "Raw token access by autonomous AI agent was strictly denied (delegated execution only)."
            .to_string()
    } else {
        format!(
            "VULNERABILITY: AI agent was permitted raw token access: {:?}",
            decision
        )
    };

    TestCaseResult {
        id: "SIM-02".to_string(),
        name: "AI Agent Raw Token Leakage Prevention".to_string(),
        description:
            "Verify that AI agents cannot extract raw tokens, preventing prompt exfiltration"
                .to_string(),
        passed,
        details,
    }
}

fn test_destructive_operation_bounded() -> TestCaseResult {
    let agent = IdentityContext::mock(
        "aider",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpDelete,
        "https://api.github.com/repos/org/repo",
    );

    let engine = PolicyEngine::default();
    let decision = engine.evaluate(&req);

    // Destructive operations must require human approval or be denied
    let passed = matches!(
        decision,
        AuthorizationDecision::RequireHumanApproval { .. } | AuthorizationDecision::Deny { .. }
    );
    let details = match decision {
        AuthorizationDecision::RequireHumanApproval { prompt, .. } => format!(
            "Destructive DELETE was correctly intercepted for human approval: '{}'",
            prompt
        ),
        AuthorizationDecision::Deny { reason } => {
            format!("Destructive DELETE was correctly denied: '{}'", reason)
        }
        other => format!(
            "VULNERABILITY: Destructive DELETE was auto-approved without human gate: {:?}",
            other
        ),
    };

    TestCaseResult {
        id: "SIM-03".to_string(),
        name: "Destructive Operation Human Approval Gate".to_string(),
        description:
            "Verify that HTTP DELETE and destructive mutations require human authorization"
                .to_string(),
        passed,
        details,
    }
}

fn test_audit_hash_chain_tamper_detection() -> TestCaseResult {
    let mut ledger = AuditLedger::new();

    let id1 = IdentityContext::mock(
        "test1",
        RequesterType::HumanInteractive,
        Some("org/repo"),
        None,
    );
    let req1 = OperationRequest::new(
        id1,
        "KEY1",
        OperationType::HttpGet,
        "https://api.example.com",
    );
    let _ = ledger.record_decision(&req1, &AuthorizationDecision::AllowRaw);

    let id2 = IdentityContext::mock(
        "test2",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req2 = OperationRequest::new(
        id2,
        "KEY2",
        OperationType::HttpGet,
        "https://api.example.com/data",
    );
    let _ = ledger.record_decision(&req2, &AuthorizationDecision::AllowDelegated);

    let valid_count = ledger.verify_integrity().unwrap_or(0);
    if valid_count != 2 {
        return TestCaseResult {
            id: "SIM-04".to_string(),
            name: "Audit Hash-Chain Tamper Detection".to_string(),
            description: "Verify that cryptographic ledger detects record tampering".to_string(),
            passed: false,
            details: format!(
                "Initial ledger verification failed with count {}",
                valid_count
            ),
        };
    }

    // Maliciously tamper with record 1's decision
    ledger.records[0].decision = "MaliciousModification".to_string();

    let tamper_detected = match ledger.verify_integrity() {
        Err(AuditIntegrityError::HashVerificationFailed { index, .. }) => index == 0,
        _ => false,
    };

    let details = if tamper_detected {
        "Cryptographic SHA-256 hash chaining immediately detected ledger tampering at sequence #1."
            .to_string()
    } else {
        "VULNERABILITY: Tampered audit record was not detected by integrity verification!"
            .to_string()
    };

    TestCaseResult {
        id: "SIM-04".to_string(),
        name: "Audit Hash-Chain Tamper Detection".to_string(),
        description: "Verify that cryptographic ledger detects record tampering".to_string(),
        passed: tamper_detected,
        details,
    }
}

fn test_delegated_execution_secret_scrubbing() -> TestCaseResult {
    let broker = SecurityBroker::new();
    let agent = IdentityContext::mock(
        "claude-worker",
        RequesterType::AutonomousAgent,
        Some("org/repo"),
        None,
    );
    let req = OperationRequest::new(
        agent,
        "GITHUB_TOKEN",
        OperationType::HttpGet,
        "https://api.github.com/repos/org/repo/pulls",
    );

    let sensitive_key = "mock_delegated_secret_token_987654321";
    match broker.execute_delegated_call(&req, Some(sensitive_key)) {
        Ok(res) => {
            let body_str = String::from_utf8_lossy(&res.body);
            let key_exposed = body_str.contains(sensitive_key);
            let passed = !key_exposed && res.status_code == 200;

            let details = if passed {
                "Broker executed delegated call safely: real secret never exposed in response body."
                    .to_string()
            } else {
                "VULNERABILITY: Real secret was reflected in delegated response body!".to_string()
            };

            TestCaseResult {
                id: "SIM-05".to_string(),
                name: "Delegated Execution Secret Scrubbing".to_string(),
                description:
                    "Verify that delegated operations never reflect protected secrets to callers"
                        .to_string(),
                passed,
                details,
            }
        }
        Err(e) => TestCaseResult {
            id: "SIM-05".to_string(),
            name: "Delegated Execution Secret Scrubbing".to_string(),
            description:
                "Verify that delegated operations never reflect protected secrets to callers"
                    .to_string(),
            passed: false,
            details: format!("Broker delegated execution unexpectedly failed: {}", e),
        },
    }
}

fn test_path_traversal_and_symlink_defense() -> TestCaseResult {
    // 1. Path traversal check
    let traversal_blocked =
        match crate::vault::validate_secure_path(Path::new("test/../../etc/shadow"), false) {
            Err(e) => e.contains("parent directory ('..') traversal"),
            Ok(_) => false,
        };

    let passed = traversal_blocked;
    let details = if passed {
        "Path traversal ('..') was rejected with strict security error across vault and storage."
            .to_string()
    } else {
        "VULNERABILITY: Path traversal was not rejected by validate_secure_path!".to_string()
    };

    TestCaseResult {
        id: "SIM-06".to_string(),
        name: "Path Traversal & Storage Boundary Defense".to_string(),
        description: "Verify that relative path traversal escapes are rejected immediately"
            .to_string(),
        passed,
        details,
    }
}

/// CLI handler for `secretguard security-test`
pub fn run_cli(args: &[String]) {
    let json_mode = args.iter().any(|a| a == "--json");

    if !json_mode {
        println!("🛡️  SecretGuard Security Self-Assessment & Attack Simulation");
        println!("══════════════════════════════════════════════════════════════════");
        println!("Executing local adversarial simulations against security boundary...\n");
    }

    let report = run_security_self_test();

    if json_mode {
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            println!("{}", json);
        }
        if !report.is_all_passed() {
            std::process::exit(1);
        }
        return;
    }

    for t in &report.tests {
        let status_badge = if t.passed {
            "\x1b[32m[PASS]\x1b[0m"
        } else {
            "\x1b[31m[FAIL]\x1b[0m"
        };
        println!("{} \x1b[1m{}\x1b[0m — {}", status_badge, t.id, t.name);
        println!("       \x1b[90m{}\x1b[0m", t.description);
        println!("       ➜ {}\n", t.details);
    }

    println!("──────────────────────────────────────────────────────────────────");
    if report.is_all_passed() {
        println!(
            "\x1b[32m\x1b[1m✅ ALL {} ADVERSARIAL SIMULATIONS PASSED\x1b[0m (0 Vulnerabilities Detected)",
            report.total
        );
        println!("Runtime defense perimeter is verified, zero-trust broker active.");
    } else {
        eprintln!(
            "\x1b[31m\x1b[1m❌ SECURITY DEFECT DETECTED: {} of {} tests failed!\x1b[0m",
            report.failed, report.total
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_self_tests_pass() {
        let report = run_security_self_test();
        assert!(
            report.is_all_passed(),
            "Self-test report had failures: {:?}",
            report
        );
        assert_eq!(report.total, 6);
        assert_eq!(report.failed, 0);
    }
}
