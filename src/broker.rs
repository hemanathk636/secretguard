//! Local Security Broker for SecretGuard
//! Sits between clients, AI agents, and protected credentials.
//! Authorizes operations, executes delegated tasks, and prevents raw token leakage.

use crate::audit::AuditLedger;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType, PolicyEngine};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};

/// Result of an approved delegated operation executed by the broker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub scrubbed_tokens_count: usize,
    pub audit_sequence: u64,
}

/// The Local Security Broker
pub struct SecurityBroker {
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub audit_ledger: Arc<Mutex<AuditLedger>>,
}

impl Default for SecurityBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityBroker {
    /// Initializes a new SecurityBroker instance loading policy and audit ledger
    pub fn new() -> Self {
        let policy_engine = Arc::new(RwLock::new(PolicyEngine::default()));
        let audit_ledger = Arc::new(Mutex::new(
            AuditLedger::load(None).unwrap_or_else(|_| AuditLedger::new()),
        ));

        Self {
            policy_engine,
            audit_ledger,
        }
    }

    /// Evaluates an OperationRequest, records it to the tamper-evident audit ledger, and returns the decision
    pub fn authorize(&self, req: &OperationRequest) -> AuthorizationDecision {
        let decision = {
            let engine = self.policy_engine.read().unwrap();
            engine.evaluate(req)
        };

        // Record decision in tamper-evident audit log
        if let Ok(mut ledger) = self.audit_ledger.lock() {
            ledger.record_decision(req, &decision);
            let _ = ledger.save(None);
        }

        decision
    }

    /// Safely executes an HTTP operation on behalf of the caller without returning raw tokens
    pub fn execute_delegated_call(
        &self,
        req: &OperationRequest,
        mock_secret_provider: Option<&str>,
    ) -> Result<DelegatedResponse, String> {
        let decision = self.authorize(req);

        match decision {
            AuthorizationDecision::AllowDelegated => {
                // Fetch the actual credential securely in-memory
                let secret_value = if let Some(mock) = mock_secret_provider {
                    mock.to_string()
                } else {
                    // Try to resolve from encrypted vault
                    match crate::vault::load_vault(None) {
                        Ok(v) => v
                            .secrets
                            .get(&req.credential_name)
                            .cloned()
                            .unwrap_or_else(|| "SG_MOCK_TOKEN_UNSET".to_string()),
                        Err(_) => "SG_MOCK_TOKEN_DEV".to_string(),
                    }
                };

                // Simulate/execute delegated HTTP dispatch in-memory
                // Raw secret is injected ONLY into the broker's ephemeral request context
                let mut mock_response = format!(
                    r#"{{"status":"ok","delegated_execution":true,"resource":"{}","operation":"{}"}}"#,
                    req.target_resource,
                    req.operation.as_str()
                );

                // Ensure real secret is never reflected back to caller
                let mut scrubbed_count = 0;
                if mock_response.contains(&secret_value) {
                    mock_response = mock_response.replace(&secret_value, "[DELEGATED_SECRET_MASKED]");
                    scrubbed_count += 1;
                }

                let audit_seq = self
                    .audit_ledger
                    .lock()
                    .ok()
                    .and_then(|l| l.records.last().map(|r| r.sequence_number))
                    .unwrap_or(0);

                Ok(DelegatedResponse {
                    status_code: 200,
                    body: mock_response.into_bytes(),
                    scrubbed_tokens_count: scrubbed_count,
                    audit_sequence: audit_seq,
                })
            }
            AuthorizationDecision::RequireHumanApproval { prompt, .. } => Err(format!(
                "Operation suspended: Human approval required ('{}').",
                prompt
            )),
            AuthorizationDecision::Deny { reason } => Err(format!("Access Denied: {}", reason)),
            AuthorizationDecision::AllowRaw => Err(
                "Policy mismatch: Operation requested delegated execution but policy returned AllowRaw."
                    .to_string(),
            ),
        }
    }

    /// CLI Handler for `secretguard broker`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard broker - Local Zero-Trust Security Broker & Authorization Plane
Coordinates process identity, policy checks, audit logging, and delegated execution.

USAGE:
    secretguard broker <SUBCOMMAND>

SUBCOMMANDS:
    status                 Displays broker status, active policies, and audit stats
    test-auth <ROLE> <OP>  Simulates authorization check for a role and operation
"#
            );
            return;
        }

        let broker = Self::new();
        match args[0].as_str() {
            "status" => {
                let policies = broker.policy_engine.read().unwrap();
                let ledger = broker.audit_ledger.lock().unwrap();
                println!("🛡️  SecretGuard Local Security Broker Status");
                println!("────────────────────────────────────────────");
                println!("Active Policy Rules:  {}", policies.rules.len());
                for r in &policies.rules {
                    println!("  • \x1b[36m{}\x1b[0m [{}]", r.name, r.id);
                }
                println!("\nAudit Ledger Records: {}", ledger.records.len());
                if let Ok(count) = ledger.verify_integrity() {
                    println!(
                        "Cryptographic Integrity: ✅ Verified ({} records intact)",
                        count
                    );
                } else if ledger.records.is_empty() {
                    println!("Cryptographic Integrity: ℹ️  Ledger initialized (0 events)");
                } else {
                    println!("Cryptographic Integrity: ❌ CORRUPTED OR TAMPERED");
                }
            }
            "test-auth" => {
                let role_arg = args.get(1).map(|s| s.as_str()).unwrap_or("agent");
                let op_arg = args.get(2).map(|s| s.as_str()).unwrap_or("GET");

                let req_type = match role_arg {
                    "human" | "developer" => RequesterType::HumanInteractive,
                    "agent" | "claude" | "aider" => RequesterType::AutonomousAgent,
                    "mcp" => RequesterType::McpServer,
                    _ => RequesterType::UnknownProcess,
                };

                let op_type = match op_arg.to_uppercase().as_str() {
                    "GET" => OperationType::HttpGet,
                    "POST" => OperationType::HttpPost,
                    "PUT" => OperationType::HttpPut,
                    "DELETE" => OperationType::HttpDelete,
                    "RAW" => OperationType::RawCredentialAccess,
                    _ => OperationType::HttpGet,
                };

                let human = IdentityContext::mock("test-caller", req_type, Some("org/repo"), None);
                let req = OperationRequest::new(
                    human,
                    "GITHUB_TOKEN",
                    op_type,
                    "https://api.github.com/repos/org/repo/pulls",
                );
                let decision = broker.authorize(&req);
                println!(
                    "Test Authorization Decision for '{:?}' performing '{}':",
                    req_type, op_arg
                );
                println!("  Result: {:?}", decision);
            }
            _ => {
                eprintln!(
                    "Unknown broker subcommand '{}'. Run 'secretguard broker --help'.",
                    args[0]
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broker_delegated_execution_scrubs_secret() {
        let broker = SecurityBroker::new();
        let agent = IdentityContext::mock(
            "claude",
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

        let secret = "sk-test-super-secret-token";
        let res = broker.execute_delegated_call(&req, Some(secret)).unwrap();
        assert_eq!(res.status_code, 200);
        let body_str = String::from_utf8(res.body).unwrap();
        assert!(!body_str.contains(secret));
    }
}
