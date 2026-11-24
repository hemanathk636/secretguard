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

static MCP_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_authenticated_ipc_and_lifecycle_integration() {
    let _guard = MCP_MUTEX.lock().unwrap();
    use secretguard::ipc::{IpcMessage, IpcServer};
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

    let auth_resp = server.handle_message_with_peer(&auth_msg, Some(std::process::id()));
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

    // Authorize operation
    let auth_op = IpcMessage::AuthorizeRequest {
        session_id,
        credential_name: "GITHUB_TOKEN".to_string(),
        operation: "GET".to_string(),
        target_resource: "https://api.github.com/repos/org/repo/pulls".to_string(),
    };
    let op_resp = server.handle_message(&auth_op);
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

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = std::fs::remove_dir_all(&test_dir);
}

#[test]
fn test_unauthenticated_ipc_and_invalid_tokens_rejected() {
    let _guard = MCP_MUTEX.lock().unwrap();
    use secretguard::ipc::{IpcMessage, IpcServer};

    let test_dir = std::env::temp_dir().join(format!("sg_ipc_reject_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&test_dir);
    std::env::set_var("SECRETGUARD_DIR", &test_dir);

    let server = IpcServer::new();

    // 1. Invalid token submitted during authentication
    let bad_auth = IpcMessage::Authenticate {
        token: "invalid_spoofed_token_value_9999".to_string(),
        client_name: "rogue-agent".to_string(),
        pid: 99999,
    };
    let bad_resp = server.handle_message(&bad_auth);
    match bad_resp {
        IpcMessage::AuthenticateResponse {
            authenticated,
            session_id,
            message,
        } => {
            assert!(
                !authenticated,
                "Authentication with invalid token must fail"
            );
            assert!(session_id.is_empty());
            assert!(message.contains("Invalid IPC authentication token"));
        }
        _ => panic!("Expected AuthenticateResponse"),
    }

    // 2. Unauthenticated caller attempting an operation with fake session ID
    let op_msg = IpcMessage::AuthorizeRequest {
        session_id: "fake_unauthenticated_session_999".to_string(),
        credential_name: "AWS_ACCESS_KEY_ID".to_string(),
        operation: "GET".to_string(),
        target_resource: "https://s3.amazonaws.com".to_string(),
    };
    let unauth_resp = server.handle_message(&op_msg);
    match unauth_resp {
        IpcMessage::Error { code, message } => {
            assert_eq!(
                code, -32001,
                "Unauthenticated calls must return standard error code -32001"
            );
            assert!(message.contains("Session expired or invalid"));
        }
        _ => panic!("Expected Error response for unauthenticated operation"),
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = std::fs::remove_dir_all(&test_dir);
}
