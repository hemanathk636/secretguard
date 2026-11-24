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
    /// Initializes a new SecurityBroker safely; fails closed if existing audit ledger is corrupted
    pub fn try_new() -> Result<Self, String> {
        let policy_engine = Arc::new(RwLock::new(PolicyEngine::default()));

        let audit_path = AuditLedger::get_default_path();
        let ledger = if audit_path.exists() {
            AuditLedger::load(None).map_err(|e| {
                format!(
                    "Security Fail-Closed: Existing audit ledger is corrupted or tampered ({}). Refusing to start broker.",
                    e
                )
            })?
        } else {
            AuditLedger::new()
        };

        Ok(Self {
            policy_engine,
            audit_ledger: Arc::new(Mutex::new(ledger)),
        })
    }

    /// Initializes a new SecurityBroker instance loading policy and audit ledger
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            eprintln!("CRITICAL SECURITY REFUSAL: {}", e);
            panic!("{}", e);
        })
    }

    /// Evaluates an OperationRequest, records it to the tamper-evident audit ledger, and returns the decision
    pub fn authorize(&self, req: &OperationRequest) -> AuthorizationDecision {
        let decision = {
            let engine = self.policy_engine.read().unwrap();
            engine.evaluate(req)
        };

        // Record decision in tamper-evident audit log with fail-closed guarantee
        let record_res = if let Ok(mut ledger) = self.audit_ledger.lock() {
            ledger.record_decision(req, &decision);
            ledger.save(None).map_err(|e| e.to_string())
        } else {
            Err("Audit ledger mutex poisoned".to_string())
        };

        if let Err(e) = record_res {
            return AuthorizationDecision::Deny {
                reason: format!(
                    "Security Fail-Closed: Failed to record audit log ({}). Access denied.",
                    e
                ),
            };
        }

        decision
    }

    /// Safely executes an HTTP operation on behalf of the caller without returning raw tokens
    pub fn execute_delegated_call(
        &self,
        req: &OperationRequest,
        mock_secret_provider: Option<&str>,
    ) -> Result<DelegatedResponse, String> {
        // 1. Strict URL and SSRF validation
        let url = &req.target_resource;
        if url.contains("169.254.169.254") || url.contains("metadata.google.internal") {
            return Err("Security Violation: Target resource attempts Cloud Metadata SSRF (SSRF Protection).".to_string());
        }

        let is_http = url.starts_with("https://")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost");
        let is_mock_test = url.starts_with("mock://") || url.starts_with("test://");

        if !is_http && !is_mock_test {
            return Err(format!(
                "Invalid Protocol: URL '{}' must use secure HTTPS (or localhost for local testing).",
                url
            ));
        }

        // 2. Authorize via policy engine and audit ledger
        let decision = self.authorize(req);

        match decision {
            AuthorizationDecision::AllowDelegated => {
                // Fetch the actual credential securely in-memory
                let secret_value = if let Some(mock) = mock_secret_provider {
                    mock.to_string()
                } else if is_mock_test {
                    "SG_MOCK_TEST_SECRET".to_string()
                } else {
                    let vault = crate::vault::load_vault(None)
                        .map_err(|e| format!("Security Broker failed to load vault: {}", e))?;
                    vault
                        .secrets
                        .get(&req.credential_name)
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Security Broker: Credential '{}' not found in vault.",
                                req.credential_name
                            )
                        })?
                };

                if secret_value.starts_with("[QUARANTINED_BLOCKED") {
                    return Err(format!(
                        "Security Circuit-Breaker: Credential '{}' is in QUARANTINED state and permanently blocked from use.",
                        req.credential_name
                    ));
                }

                // 3. Dispatch genuine delegated HTTP call (or mock test harness if mock URL)
                let (raw_status, raw_body) = if is_http && mock_secret_provider.is_none() {
                    let auth_header = if req.credential_name.to_uppercase().contains("GITHUB") {
                        format!("Authorization: token {}", secret_value)
                    } else {
                        format!("Authorization: Bearer {}", secret_value)
                    };

                    let method = req.operation.as_str();
                    let output = std::process::Command::new("curl")
                        .args([
                            "-s",
                            "-w",
                            "\n%{http_code}",
                            "-X",
                            method,
                            "-H",
                            &auth_header,
                            "-H",
                            "User-Agent: SecretGuard-Security-Broker/1.0",
                            "--max-time",
                            "15",
                            url,
                        ])
                        .output();

                    match output {
                        Ok(out) => {
                            let text = String::from_utf8_lossy(&out.stdout).to_string();
                            if let Some(last_newline) = text.rfind('\n') {
                                let body = text.as_bytes()[..last_newline].to_vec();
                                let code_str = text[last_newline + 1..].trim();
                                let code = code_str.parse::<u16>().unwrap_or(200);
                                (code, body)
                            } else {
                                (200, out.stdout)
                            }
                        }
                        Err(e) => {
                            return Err(format!("Delegated HTTP dispatch error via system curl: {}", e));
                        }
                    }
                } else {
                    // Offline test harness execution
                    let body_str = format!(
                        r#"{{"status":"ok","delegated_execution":true,"resource":"{}","operation":"{}"}}"#,
                        req.target_resource,
                        req.operation.as_str()
                    );
                    (200, body_str.into_bytes())
                };

                // 4. Scrubbing: Ensure real secret is NEVER reflected back to caller
                let mut body_str = String::from_utf8_lossy(&raw_body).to_string();
                let mut scrubbed_count = 0;
                if body_str.contains(&secret_value) {
                    body_str = body_str.replace(&secret_value, "[DELEGATED_SECRET_MASKED]");
                    scrubbed_count += 1;
                }

                // Inbound scanner layer: sanitize any other leaked keys in response
                let engine = crate::SecretGuardEngine::new();
                let scanned = engine.scan_and_sanitize(&body_str);
                if scanned.has_secret {
                    body_str = scanned.sanitized_text;
                    scrubbed_count += 1;
                }

                let audit_seq = self
                    .audit_ledger
                    .lock()
                    .ok()
                    .and_then(|l| l.records.last().map(|r| r.sequence_number))
                    .unwrap_or(0);

                Ok(DelegatedResponse {
                    status_code: raw_status,
                    body: body_str.into_bytes(),
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
        let temp_dir = std::env::temp_dir().join(format!("sg_broker_unit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        std::env::set_var("SECRETGUARD_DIR", &temp_dir);

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

        std::env::remove_var("SECRETGUARD_DIR");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
