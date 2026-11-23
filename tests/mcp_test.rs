use secretguard::SecretGuardEngine;

#[test]
fn test_mcp_engine_redaction() {
    let engine = SecretGuardEngine::new();
    let sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let res = engine.scan_and_sanitize(sample);

    assert!(res.has_secret);
    assert!(!res.sanitized_text.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(res.sanitized_text.contains("[REDACTED]"));
}

#[test]
fn test_mcp_clean_input() {
    let engine = SecretGuardEngine::new();
    let sample = "git status && cargo build --release";
    let res = engine.scan_and_sanitize(sample);

    assert!(!res.has_secret);
    assert_eq!(res.sanitized_text, sample);
    assert_eq!(res.synthetic_text, sample);
}

#[test]
fn test_synthetic_mock_generation() {
    let engine = SecretGuardEngine::new();

    // Test AWS key length & prefix preservation
    let aws = "export AWS=AKIAIOSFODNN7EXAMPLE";
    let res = engine.scan_and_sanitize(aws);
    assert!(res.has_secret);
    assert!(res.synthetic_text.contains("AKIAFAKE"));
    assert_eq!(res.synthetic_text.len(), aws.len());

    // Test OpenAI Project Key preservation
    let openai = "OPENAI_API_KEY=sk-proj-123456789012345678901234567890123456789012345678";
    let res_ai = engine.scan_and_sanitize(openai);
    assert!(res_ai.has_secret);
    assert!(res_ai
        .synthetic_text
        .starts_with("OPENAI_API_KEY=sk-proj-TESTDUMMYMOCK"));
    assert_eq!(res_ai.synthetic_text.len(), openai.len());

    // Test GitHub Token preservation
    let gh = "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234";
    let res_gh = engine.scan_and_sanitize(gh);
    assert!(res_gh.has_secret);
    assert!(res_gh
        .synthetic_text
        .starts_with("GITHUB_TOKEN=ghp_TESTDUMMYMOCK"));
    assert_eq!(res_gh.synthetic_text.len(), gh.len());
}

#[test]
fn test_mcp_security_gateway_inspection() {
    let engine = SecretGuardEngine::new();

    // 1. Safe tool call arguments
    let safe_args = r#"{"repo": "myorg/project", "action": "list_issues"}"#;
    let res_safe = engine.scan_and_sanitize(safe_args);
    assert!(!res_safe.has_secret);

    // 2. Sensitive tool call leaking OpenAI key
    let leaking_args = r#"{"prompt": "hello", "api_key": "sk-proj-123456789012345678901234567890123456789012345678"}"#;
    let res_leak = engine.scan_and_sanitize(leaking_args);
    assert!(res_leak.has_secret);
    assert!(!res_leak
        .sanitized_text
        .contains("sk-proj-123456789012345678901234567890123456789012345678"));
}

#[test]
fn test_authenticated_ipc_and_lifecycle_integration() {
    use secretguard::ipc::{AuthenticatedSession, IpcMessage, IpcServer};
    use secretguard::lifecycle::LifecycleManager;

    let test_dir = std::env::temp_dir().join(format!("sg_ipc_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&test_dir);
    std::env::set_var("SECRETGUARD_DIR", &test_dir);

    let server = IpcServer::new();
    let auth_token = IpcServer::get_or_create_token().expect("derive token");

    // Authenticate
    let auth_msg = IpcMessage::Authenticate {
        token: auth_token,
        client_name: "claude-code".to_string(),
        pid: std::process::id(),
    };

    let auth_resp = server.handle_message(None, &auth_msg);
    let session_id = match auth_resp {
        IpcMessage::AuthenticateResponse {
            authenticated,
            session_id,
            ..
        } => {
            assert!(authenticated);
            session_id
        }
        _ => panic!("Expected AuthenticateResponse"),
    };

    let session = AuthenticatedSession {
        session_id,
        client_name: "claude-code".to_string(),
        pid: std::process::id(),
        requester_type: secretguard::identity::RequesterType::AutonomousAgent,
        established_at: 1000,
    };

    // Authorize operation
    let auth_op = IpcMessage::AuthorizeRequest {
        credential_name: "GITHUB_TOKEN".to_string(),
        operation: "GET".to_string(),
        target_resource: "https://api.github.com/repos/org/repo/pulls".to_string(),
    };
    let op_resp = server.handle_message(Some(&session), &auth_op);
    match op_resp {
        IpcMessage::AuthorizeResponse {
            allowed, decision, ..
        } => {
            assert!(allowed);
            assert_eq!(decision, "AllowDelegated");
        }
        _ => panic!("Expected AuthorizeResponse"),
    }

    // Verify Lifecycle tracking
    let mut lm = LifecycleManager::new();
    lm.register("GITHUB_TOKEN", "GitHub PAT", "ghp_mocktest1234567890abcdef");
    assert!(lm.record_usage("GITHUB_TOKEN"));
    lm.quarantine_credential("GITHUB_TOKEN", "Exposed in log");
    assert!(!lm.record_usage("GITHUB_TOKEN"));

    let _ = std::fs::remove_dir_all(&test_dir);
}
