//! Central Operation-Aware Policy & Authorization Engine for SecretGuard
//! Evaluates identity, repository context, operation, target domain, and credential role.

use crate::identity::{IdentityContext, RequesterType, TrustTier};
use serde::{Deserialize, Serialize};

/// Specific operation requested by a client
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    HttpGet,
    HttpPost,
    HttpPut,
    HttpDelete,
    HttpPatch,
    GitFetch,
    GitPush,
    McpToolCall(String),
    RawCredentialAccess,
    DelegatedProcessExec,
}

impl OperationType {
    pub fn as_str(&self) -> &str {
        match self {
            OperationType::HttpGet => "GET",
            OperationType::HttpPost => "POST",
            OperationType::HttpPut => "PUT",
            OperationType::HttpDelete => "DELETE",
            OperationType::HttpPatch => "PATCH",
            OperationType::GitFetch => "git:fetch",
            OperationType::GitPush => "git:push",
            OperationType::McpToolCall(_) => "mcp:call",
            OperationType::RawCredentialAccess => "raw:read",
            OperationType::DelegatedProcessExec => "exec:inject",
        }
    }
}

/// Rich operation request submitted for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    pub requester: IdentityContext,
    pub credential_name: String,
    pub operation: OperationType,
    pub target_resource: String,
    pub target_domain: Option<String>,
    pub repository: Option<String>,
}

impl OperationRequest {
    pub fn new(
        requester: IdentityContext,
        credential_name: &str,
        operation: OperationType,
        target_resource: &str,
    ) -> Self {
        let domain = extract_domain(target_resource);
        let repo = if domain.is_some() {
            crate::identity::extract_repository_from_url(target_resource)
                .or_else(|| requester.git_repo.clone())
        } else {
            None
        };
        Self {
            requester,
            credential_name: credential_name.to_string(),
            operation,
            target_resource: target_resource.to_string(),
            target_domain: domain,
            repository: repo,
        }
    }
}

/// Extracted domain from target URL or resource using canonical parser (strictly forbidding userinfo @)
fn extract_domain(resource: &str) -> Option<String> {
    crate::broker::parse_canonical_url(resource)
        .ok()
        .map(|u| u.host)
}

/// Authorization evaluation result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationDecision {
    /// Operation approved for execution via the broker; credential remains in memory
    AllowDelegated,
    /// Raw secret may be returned directly (restricted to Tier 3 human interactive sessions)
    AllowRaw,
    /// Operation requires explicit interactive human approval
    RequireHumanApproval { prompt: String, risk_level: String },
    /// Operation strictly denied (fail closed)
    Deny { reason: String },
}

impl AuthorizationDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AuthorizationDecision::AllowDelegated | AuthorizationDecision::AllowRaw
        )
    }
}

/// Declarative policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub allowed_roles: Vec<RequesterType>,
    pub min_trust_tier: TrustTier,
    pub allowed_credentials: Vec<String>,
    pub allowed_repositories: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_operations: Vec<String>,
    pub denied_operations: Vec<String>,
    pub approval_required_for: Vec<String>,
    pub delegate_only: bool,
}

/// Detailed policy evaluation trace for auditability and `policy explain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExplanation {
    pub decision: AuthorizationDecision,
    pub matched_rule_ids: Vec<String>,
    pub denied_by: Vec<String>,
    pub approval_required_by: Vec<String>,
    pub allowed_by: Vec<String>,
    pub explanation: String,
}

/// Validation result for `PolicyEngine::validate` and `secretguard policy validate`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Central Policy Engine evaluating operation requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngine {
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_secure_defaults()
    }
}

impl PolicyEngine {
    /// Constructs a policy engine loaded with standard zero-trust defaults
    pub fn with_secure_defaults() -> Self {
        let rules = vec![
            // 1. Human Developer Interactive Override
            PolicyRule {
                id: "rule-human-dev-privileged".to_string(),
                name: "Human Interactive Developer Session".to_string(),
                allowed_roles: vec![RequesterType::HumanInteractive],
                min_trust_tier: TrustTier::Tier3Privileged,
                allowed_credentials: vec!["*".to_string()],
                allowed_repositories: vec!["*".to_string()],
                allowed_domains: vec!["*".to_string()],
                allowed_operations: vec!["*".to_string()],
                denied_operations: vec![],
                approval_required_for: vec![],
                delegate_only: false,
            },
            // 2. AI Coding Agent Repository-Bound Delegated Execution
            PolicyRule {
                id: "rule-agent-github-pr-review".to_string(),
                name: "AI Coding Assistant Delegated GitHub Access".to_string(),
                allowed_roles: vec![
                    RequesterType::AutonomousAgent,
                    RequesterType::ApprovedIde,
                    RequesterType::McpServer,
                    RequesterType::BuildOrScript,
                ],
                min_trust_tier: TrustTier::Tier1Restricted,
                allowed_credentials: vec!["GITHUB_TOKEN".to_string(), "GH_TOKEN".to_string()],
                allowed_repositories: vec!["$CURRENT_REPO".to_string()],
                allowed_domains: vec!["api.github.com".to_string(), "github.com".to_string()],
                allowed_operations: vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "PATCH".to_string(),
                    "git:fetch".to_string(),
                ],
                denied_operations: vec!["DELETE".to_string(), "raw:read".to_string()],
                approval_required_for: vec![
                    "POST".to_string(),
                    "PUT".to_string(),
                    "PATCH".to_string(),
                ],
                delegate_only: true, // Never give raw token to AI agent
            },
            // 3. AI Coding Agent LLM Provider API Delegated Access
            PolicyRule {
                id: "rule-agent-llm-provider-api".to_string(),
                name: "AI Agent LLM Inference API Calls".to_string(),
                allowed_roles: vec![
                    RequesterType::AutonomousAgent,
                    RequesterType::ApprovedIde,
                    RequesterType::McpServer,
                    RequesterType::BuildOrScript,
                ],
                min_trust_tier: TrustTier::Tier1Restricted,
                allowed_credentials: vec![
                    "OPENAI_API_KEY".to_string(),
                    "ANTHROPIC_API_KEY".to_string(),
                    "GEMINI_API_KEY".to_string(),
                ],
                allowed_repositories: vec!["$CURRENT_REPO".to_string()],
                allowed_domains: vec![
                    "api.openai.com".to_string(),
                    "api.anthropic.com".to_string(),
                    "generativelanguage.googleapis.com".to_string(),
                ],
                allowed_operations: vec!["POST".to_string(), "GET".to_string()],
                denied_operations: vec!["DELETE".to_string(), "raw:read".to_string()],
                approval_required_for: vec![],
                delegate_only: true,
            },
            // 4. Local Delegated Subprocess Injection (`vault run`) for Build/CI
            PolicyRule {
                id: "rule-local-delegated-exec".to_string(),
                name: "Local Delegated Subprocess Secret Injection".to_string(),
                allowed_roles: vec![RequesterType::BuildOrScript],
                min_trust_tier: TrustTier::Tier1Restricted,
                allowed_credentials: vec!["*".to_string()],
                allowed_repositories: vec!["*".to_string()],
                allowed_domains: vec!["*".to_string()],
                allowed_operations: vec!["exec:inject".to_string()],
                denied_operations: vec!["raw:read".to_string()],
                approval_required_for: vec![],
                delegate_only: true,
            },
        ];

        Self { rules }
    }

    fn rule_matches_scope(rule: &PolicyRule, req: &OperationRequest) -> bool {
        if !rule.allowed_roles.contains(&req.requester.requester_type) {
            return false;
        }
        if req.requester.trust_tier < rule.min_trust_tier {
            return false;
        }
        if !rule
            .allowed_credentials
            .iter()
            .any(|c| c == "*" || c.eq_ignore_ascii_case(&req.credential_name))
        {
            return false;
        }
        if !rule.allowed_domains.iter().any(|d| d == "*") {
            match &req.target_domain {
                Some(dom) => {
                    if !rule
                        .allowed_domains
                        .iter()
                        .any(|d| d.eq_ignore_ascii_case(dom))
                    {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if !rule.allowed_repositories.iter().any(|r| r == "*") {
            match &req.repository {
                Some(repo) => {
                    let repo_allowed = rule.allowed_repositories.iter().any(|r| {
                        if r == "$CURRENT_REPO" || r == "$ACTIVE_REPO" {
                            req.requester
                                .git_repo
                                .as_ref()
                                .is_some_and(|caller_repo| caller_repo.eq_ignore_ascii_case(repo))
                        } else {
                            r.eq_ignore_ascii_case(repo)
                        }
                    });
                    if !repo_allowed {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Validates rule definitions and detects conflicting or malformed policies.
    pub fn validate(&self) -> PolicyValidationReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        if self.rules.is_empty() {
            warnings
                .push("PolicyEngine has 0 rules; all requests will hit Default Deny.".to_string());
        }

        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                errors.push(format!("Rule '{}' has an empty rule ID.", rule.name));
            } else if !seen_ids.insert(rule.id.clone()) {
                errors.push(format!("Duplicate policy rule ID '{}'.", rule.id));
            }
            if rule.allowed_roles.is_empty() {
                errors.push(format!("Rule '{}' has empty allowed_roles.", rule.id));
            }
            if rule.allowed_operations.is_empty() && rule.denied_operations.is_empty() {
                warnings.push(format!(
                    "Rule '{}' specifies neither allowed_operations nor denied_operations.",
                    rule.id
                ));
            }
            for op in &rule.allowed_operations {
                if rule.denied_operations.iter().any(|d| d == op || d == "*") {
                    warnings.push(format!(
                        "Rule '{}' lists '{}' in both allowed_operations and denied_operations (Deny takes precedence).",
                        rule.id, op
                    ));
                }
            }
        }

        // Cross-rule conflict detection
        for (i, r1) in self.rules.iter().enumerate() {
            for r2 in self.rules.iter().skip(i + 1) {
                let roles_overlap = r1
                    .allowed_roles
                    .iter()
                    .any(|role| r2.allowed_roles.contains(role));
                let creds_overlap = r1.allowed_credentials.iter().any(|c1| {
                    r2.allowed_credentials
                        .iter()
                        .any(|c2| c1 == "*" || c2 == "*" || c1.eq_ignore_ascii_case(c2))
                });
                if !roles_overlap || !creds_overlap {
                    continue;
                }
                for op in &r1.allowed_operations {
                    if r2.denied_operations.iter().any(|d| d == op || d == "*") {
                        warnings.push(format!(
                            "Cross-rule precedence: '{}' allows '{}' while '{}' denies '{}' (Deny overrides Allow).",
                            r1.id, op, r2.id, op
                        ));
                    }
                }
            }
        }

        PolicyValidationReport {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Evaluates an OperationRequest across all matching rules with deterministic precedence:
    /// Quarantined / Tier0 / Raw-Agent Guard > Explicit Deny > RequireHumanApproval > Allow > Default Deny.
    pub fn evaluate_with_explanation(&self, req: &OperationRequest) -> PolicyExplanation {
        if req.credential_name.starts_with("QUARANTINED_") {
            let reason = format!(
                "Security Circuit-Breaker: Credential '{}' is in QUARANTINED state and permanently blocked from use.",
                req.credential_name
            );
            return PolicyExplanation {
                decision: AuthorizationDecision::Deny {
                    reason: reason.clone(),
                },
                matched_rule_ids: Vec::new(),
                denied_by: vec!["circuit-breaker-quarantine".to_string()],
                approval_required_by: Vec::new(),
                allowed_by: Vec::new(),
                explanation: reason,
            };
        }

        if req.requester.trust_tier == TrustTier::Tier0Blocked {
            let reason = format!(
                "Security Violation: Process '{}' (PID {}) is classified as untrusted or blocked.",
                req.requester.executable_name, req.requester.pid
            );
            return PolicyExplanation {
                decision: AuthorizationDecision::Deny {
                    reason: reason.clone(),
                },
                matched_rule_ids: Vec::new(),
                denied_by: vec!["trust-tier0-block".to_string()],
                approval_required_by: Vec::new(),
                allowed_by: Vec::new(),
                explanation: reason,
            };
        }

        if req.operation == OperationType::RawCredentialAccess
            && req.requester.requester_type != RequesterType::HumanInteractive
        {
            let reason = format!(
                "Zero-Trust Policy: Raw credential exposure strictly prohibited for {:?}. Use delegated broker execution.",
                req.requester.requester_type
            );
            return PolicyExplanation {
                decision: AuthorizationDecision::Deny {
                    reason: reason.clone(),
                },
                matched_rule_ids: Vec::new(),
                denied_by: vec!["zero-trust-raw-guard".to_string()],
                approval_required_by: Vec::new(),
                allowed_by: Vec::new(),
                explanation: reason,
            };
        }

        let op_str = req.operation.as_str();
        let mut matched_rule_ids = Vec::new();
        let mut denied_by = Vec::new();
        let mut deny_reasons = Vec::new();
        let mut approval_required_by = Vec::new();
        let mut allowed_by = Vec::new();
        let mut any_delegate_only = false;

        for rule in &self.rules {
            if !Self::rule_matches_scope(rule, req) {
                continue;
            }
            matched_rule_ids.push(rule.id.clone());

            if rule
                .denied_operations
                .iter()
                .any(|d| d == "*" || d == op_str)
            {
                denied_by.push(rule.id.clone());
                deny_reasons.push(format!(
                    "Operation '{}' is explicitly forbidden by policy rule '{}'.",
                    op_str, rule.name
                ));
                continue;
            }

            if !rule
                .allowed_operations
                .iter()
                .any(|a| a == "*" || a == op_str)
            {
                continue;
            }

            if rule.delegate_only {
                any_delegate_only = true;
            }

            if rule
                .approval_required_for
                .iter()
                .any(|appr| appr == "*" || appr == op_str)
            {
                approval_required_by.push(rule.id.clone());
            } else {
                allowed_by.push(rule.id.clone());
            }
        }

        if !denied_by.is_empty() {
            let reason = deny_reasons.join(" | ");
            return PolicyExplanation {
                decision: AuthorizationDecision::Deny {
                    reason: reason.clone(),
                },
                matched_rule_ids,
                denied_by,
                approval_required_by,
                allowed_by,
                explanation: reason,
            };
        }

        if !approval_required_by.is_empty() {
            let prompt = format!(
                "Caller '{}' (PID {}) requests permission to perform '{}' on '{}' using credential '{}'. Approve?",
                req.requester.executable_name,
                req.requester.pid,
                op_str,
                req.target_resource,
                req.credential_name
            );
            let risk_level = if op_str == "DELETE" || op_str == "git:push" || op_str == "raw:read" {
                "HIGH".to_string()
            } else {
                "MEDIUM".to_string()
            };
            let explanation = format!(
                "Human approval required by rule(s) [{}].",
                approval_required_by.join(", ")
            );
            return PolicyExplanation {
                decision: AuthorizationDecision::RequireHumanApproval { prompt, risk_level },
                matched_rule_ids,
                denied_by,
                approval_required_by,
                allowed_by,
                explanation,
            };
        }

        if !allowed_by.is_empty() {
            let decision = if any_delegate_only
                || req.requester.requester_type != RequesterType::HumanInteractive
            {
                AuthorizationDecision::AllowDelegated
            } else {
                AuthorizationDecision::AllowRaw
            };
            let explanation = format!(
                "Permitted ({:?}) by rule(s) [{}].",
                decision,
                allowed_by.join(", ")
            );
            return PolicyExplanation {
                decision,
                matched_rule_ids,
                denied_by,
                approval_required_by,
                allowed_by,
                explanation,
            };
        }

        let reason = format!(
            "Default Deny: No policy permits {:?} to perform '{}' using credential '{}' against '{}'.",
            req.requester.requester_type, op_str, req.credential_name, req.target_resource
        );
        PolicyExplanation {
            decision: AuthorizationDecision::Deny {
                reason: reason.clone(),
            },
            matched_rule_ids,
            denied_by,
            approval_required_by,
            allowed_by,
            explanation: reason,
        }
    }

    /// Evaluates an OperationRequest against active policy rules
    pub fn evaluate(&self, req: &OperationRequest) -> AuthorizationDecision {
        self.evaluate_with_explanation(req).decision
    }

    /// CLI handler for `secretguard policy`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard policy - Central Operation-Aware Policy & Authorization Engine
Inspect and manage zero-trust operation rules, role mappings, and scopes.

USAGE:
    secretguard policy <SUBCOMMAND>

SUBCOMMANDS:
    list                            List active policy rules, roles, and allowed operations
    validate                        Validate policy rule definitions and detect conflicts
    explain <KEY> <OP> [RESOURCE]   Evaluate policy and show rule matching & precedence trace
    check <KEY> <OP> [RESOURCE]     Evaluate policy for the calling terminal process
    eval <ROLE> <KEY> <OP> [URL]    Test policy decision for a simulated role and operation
"#
            );
            return;
        }

        let engine = Self::default();
        match args[0].as_str() {
            "validate" => {
                let report = engine.validate();
                println!(
                    "Policy Validation: {} ({} rule(s), {} error(s), {} warning(s))",
                    if report.valid { "VALID" } else { "INVALID" },
                    engine.rules.len(),
                    report.errors.len(),
                    report.warnings.len()
                );
                for err in &report.errors {
                    eprintln!("  ❌ Error: {}", err);
                }
                for warn in &report.warnings {
                    println!("  ⚠️  Warning: {}", warn);
                }
                if !report.valid {
                    std::process::exit(1);
                }
            }
            "explain" => {
                let key = args.get(1).map(|s| s.as_str()).unwrap_or("GITHUB_TOKEN");
                let op_str = args.get(2).map(|s| s.as_str()).unwrap_or("GET");
                let resource = args
                    .get(3)
                    .map(|s| s.as_str())
                    .unwrap_or("https://api.github.com");
                let op = match op_str.to_uppercase().as_str() {
                    "GET" => OperationType::HttpGet,
                    "POST" => OperationType::HttpPost,
                    "PUT" => OperationType::HttpPut,
                    "DELETE" => OperationType::HttpDelete,
                    "RAW" => OperationType::RawCredentialAccess,
                    _ => OperationType::HttpGet,
                };
                let caller = IdentityContext::current();
                let req = OperationRequest::new(caller, key, op, resource);
                let trace = engine.evaluate_with_explanation(&req);
                println!("Matched Rules:    {:?}", trace.matched_rule_ids);
                println!("Denied By:        {:?}", trace.denied_by);
                println!("Approval By:      {:?}", trace.approval_required_by);
                println!("Allowed By:       {:?}", trace.allowed_by);
                println!("Decision:         {:?}", trace.decision);
                println!("Explanation:      {}", trace.explanation);
            }
            "list" => {
                println!("🛡️  SecretGuard Active Authorization Policy Rules");
                println!("──────────────────────────────────────────────────────────────────");
                for (idx, rule) in engine.rules.iter().enumerate() {
                    println!(
                        "\x1b[1m{:2}. {}\x1b[0m [\x1b[36m{}\x1b[0m]",
                        idx + 1,
                        rule.name,
                        rule.id
                    );
                    println!("    Allowed Roles:        {:?}", rule.allowed_roles);
                    println!("    Min Trust Tier:       {:?}", rule.min_trust_tier);
                    println!(
                        "    Allowed Credentials:  {}",
                        rule.allowed_credentials.join(", ")
                    );
                    println!(
                        "    Allowed Operations:   {}",
                        rule.allowed_operations.join(", ")
                    );
                    println!(
                        "    Delegated Execution:  {}",
                        if rule.delegate_only {
                            "Enforced (No Raw Secrets)"
                        } else {
                            "Optional"
                        }
                    );
                    println!(
                        "    Approval Required:    {}",
                        if rule.approval_required_for.is_empty() {
                            "None".to_string()
                        } else {
                            rule.approval_required_for.join(", ")
                        }
                    );
                }
            }
            "check" => {
                let key = args.get(1).map(|s| s.as_str()).unwrap_or("GITHUB_TOKEN");
                let op_str = args.get(2).map(|s| s.as_str()).unwrap_or("GET");
                let resource = args
                    .get(3)
                    .map(|s| s.as_str())
                    .unwrap_or("https://api.github.com");

                let op = match op_str.to_uppercase().as_str() {
                    "GET" => OperationType::HttpGet,
                    "POST" => OperationType::HttpPost,
                    "PUT" => OperationType::HttpPut,
                    "DELETE" => OperationType::HttpDelete,
                    "RAW" => OperationType::RawCredentialAccess,
                    _ => OperationType::HttpGet,
                };

                let caller = IdentityContext::current();
                println!("Caller Process Identity:");
                println!("  PID:           {}", caller.pid);
                println!("  Name:          {}", caller.executable_name);
                println!("  RequesterType: {:?}", caller.requester_type);
                println!(
                    "  TrustTier:     {:?} (Score: {})",
                    caller.trust_tier, caller.trust_score
                );
                println!("  Git Repo:      {:?}", caller.git_repo);

                let req = OperationRequest::new(caller, key, op, resource);
                let decision = engine.evaluate(&req);
                println!("\nAuthorization Decision:");
                match decision {
                    AuthorizationDecision::AllowDelegated => {
                        println!("  \x1b[32mALLOW (Delegated Execution Only)\x1b[0m");
                    }
                    AuthorizationDecision::AllowRaw => {
                        println!("  \x1b[32mALLOW (Raw Credential Permitted)\x1b[0m");
                    }
                    AuthorizationDecision::RequireHumanApproval { prompt, .. } => {
                        println!("  \x1b[33mREQUIRE HUMAN APPROVAL\x1b[0m: {}", prompt);
                    }
                    AuthorizationDecision::Deny { reason } => {
                        println!("  \x1b[31mDENY\x1b[0m: {}", reason);
                    }
                }
            }
            "eval" => {
                let role_str = args.get(1).map(|s| s.as_str()).unwrap_or("agent");
                let key = args.get(2).map(|s| s.as_str()).unwrap_or("GITHUB_TOKEN");
                let op_str = args.get(3).map(|s| s.as_str()).unwrap_or("GET");
                let resource = args
                    .get(4)
                    .map(|s| s.as_str())
                    .unwrap_or("https://api.github.com/repos/org/repo/pulls");

                let req_type = match role_str.to_lowercase().as_str() {
                    "human" | "dev" | "developer" => RequesterType::HumanInteractive,
                    "ide" | "vscode" | "cursor" => RequesterType::ApprovedIde,
                    "agent" | "claude" | "aider" => RequesterType::AutonomousAgent,
                    "mcp" => RequesterType::McpServer,
                    "build" | "ci" | "script" => RequesterType::BuildOrScript,
                    _ => RequesterType::UnknownProcess,
                };

                let op = match op_str.to_uppercase().as_str() {
                    "GET" => OperationType::HttpGet,
                    "POST" => OperationType::HttpPost,
                    "PUT" => OperationType::HttpPut,
                    "DELETE" => OperationType::HttpDelete,
                    "RAW" => OperationType::RawCredentialAccess,
                    _ => OperationType::HttpGet,
                };

                let ident = IdentityContext::mock("eval-caller", req_type, Some("org/repo"), None);
                let req = OperationRequest::new(ident, key, op, resource);
                let decision = engine.evaluate(&req);
                println!(
                    "Simulated Evaluation for Role {:?} on {} ({}):",
                    req_type, key, op_str
                );
                println!("  Decision: {:?}", decision);
            }
            _ => {
                eprintln!(
                    "Unknown policy subcommand '{}'. Run 'secretguard policy --help'.",
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
    fn test_human_interactive_privileged_access() {
        let engine = PolicyEngine::default();
        let human = IdentityContext::mock(
            "bash",
            RequesterType::HumanInteractive,
            Some("org/repo"),
            None,
        );
        let req = OperationRequest::new(
            human,
            "GITHUB_TOKEN",
            OperationType::RawCredentialAccess,
            "https://api.github.com",
        );

        let decision = engine.evaluate(&req);
        assert_eq!(decision, AuthorizationDecision::AllowRaw);
    }

    #[test]
    fn test_ai_agent_raw_credential_access_strictly_denied() {
        let engine = PolicyEngine::default();
        let agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("org/repo"),
            None,
        );
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::RawCredentialAccess,
            "https://api.github.com",
        );

        let decision = engine.evaluate(&req);
        assert!(matches!(decision, AuthorizationDecision::Deny { .. }));
    }

    #[test]
    fn test_ai_agent_delegated_get_allowed() {
        let engine = PolicyEngine::default();
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

        let decision = engine.evaluate(&req);
        assert_eq!(decision, AuthorizationDecision::AllowDelegated);
    }

    #[test]
    fn test_ai_agent_post_triggers_human_approval() {
        let engine = PolicyEngine::default();
        let agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("org/repo"),
            None,
        );
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpPost,
            "https://api.github.com/repos/org/repo/issues",
        );

        let decision = engine.evaluate(&req);
        assert!(matches!(
            decision,
            AuthorizationDecision::RequireHumanApproval { .. }
        ));
    }

    #[test]
    fn test_ai_agent_delete_strictly_denied() {
        let engine = PolicyEngine::default();
        let agent = IdentityContext::mock(
            "claude",
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

        let decision = engine.evaluate(&req);
        assert!(matches!(decision, AuthorizationDecision::Deny { .. }));
    }

    #[test]
    fn test_untrusted_process_denied_fail_closed() {
        let engine = PolicyEngine::default();
        let rogue =
            IdentityContext::mock("unknown_script", RequesterType::UnknownProcess, None, None);
        let req = OperationRequest::new(
            rogue,
            "ANY_TOKEN",
            OperationType::HttpGet,
            "https://evil.com",
        );

        let decision = engine.evaluate(&req);
        assert!(matches!(decision, AuthorizationDecision::Deny { .. }));
    }

    #[test]
    fn test_ai_agent_cross_repo_access_denied() {
        let engine = PolicyEngine::default();
        let agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("attacker-org/repo-a"),
            None,
        );
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpGet,
            "https://api.github.com/repos/victim-org/repo-b/pulls",
        );

        let decision = engine.evaluate(&req);
        assert!(
            matches!(decision, AuthorizationDecision::Deny { .. }),
            "Cross-repository access must be strictly denied"
        );
    }

    #[test]
    fn test_ai_agent_no_repo_context_denied() {
        let engine = PolicyEngine::default();
        let agent = IdentityContext::mock("claude", RequesterType::AutonomousAgent, None, None);
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpGet,
            "https://api.github.com/repos/org/repo/pulls",
        );

        let decision = engine.evaluate(&req);
        assert!(
            matches!(decision, AuthorizationDecision::Deny { .. }),
            "Access without caller repository context must be fail-closed denied"
        );
    }
}
