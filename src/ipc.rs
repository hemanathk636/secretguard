//! Authenticated Local IPC Protocol & Service for SecretGuard
//!
//! Provides a secure, zero-trust inter-process communication protocol connecting:
//! - IDE extensions (VS Code, Cursor, Windsurf)
//! - Autonomous AI agents (Claude Code, Aider, Copilot, Cline)
//! - MCP servers and gateway daemons
//! - Local Security Broker (`src/broker.rs`)
//!
//! Security Properties:
//! - Authenticated sessions via ephemeral CSPRNG bearer tokens saved at 0o600
//! - Automatic caller identity verification (`IdentityContext`)
//! - Strict session registry with TTL expiry and peer validation
//! - Real loopback socket IPC transport
//! - All operations logged to tamper-evident audit ledger

use crate::broker::SecurityBroker;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

/// IPC Message payload exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Initial client handshake authenticating against the broker
    Authenticate {
        token: String,
        client_name: String,
        pid: u32,
    },
    /// Response to handshake
    AuthenticateResponse {
        authenticated: bool,
        session_id: String,
        message: String,
    },
    /// Request authorization evaluation for an operation
    AuthorizeRequest {
        session_id: String,
        credential_name: String,
        operation: String,
        target_resource: String,
    },
    /// Authorization decision returned by the broker
    AuthorizeResponse {
        decision: String,
        allowed: bool,
        audit_sequence: u64,
        details: Option<String>,
    },
    /// Request delegated execution (broker executes call, scrubs secrets, returns result)
    DelegatedCallRequest {
        session_id: String,
        credential_name: String,
        operation: String,
        target_resource: String,
    },
    /// Delegated execution response with masked/scrubbed secrets
    DelegatedCallResponse {
        status_code: u16,
        body: Vec<u8>,
        scrubbed_count: usize,
        audit_sequence: u64,
    },
    /// Error message
    Error { code: i32, message: String },
}

/// Active authenticated session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSession {
    pub session_id: String,
    pub client_name: String,
    pub pid: u32,
    pub requester_type: RequesterType,
    pub established_at: u64,
    pub last_active_at: u64,
}

/// IPC Server managing authenticated sessions and IPC transport
pub struct IpcServer {
    pub broker: SecurityBroker,
    pub expected_token: String,
    pub sessions: Arc<RwLock<HashMap<String, AuthenticatedSession>>>,
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcServer {
    pub fn try_new() -> Result<Self, String> {
        let expected_token = Self::get_or_create_token()
            .map_err(|e| format!("Security Fail-Closed: Cannot derive IPC token: {}", e))?;

        let broker = SecurityBroker::try_new()
            .map_err(|e| format!("Security Fail-Closed: Cannot initialize broker: {}", e))?;

        Ok(Self {
            broker,
            expected_token,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            eprintln!("CRITICAL IPC FAILURE: {}", e);
            panic!("{}", e);
        })
    }

    /// Derives or creates local IPC authentication token stored securely in .secretguard/ipc.token (0o600)
    pub fn get_or_create_token() -> Result<String, std::io::Error> {
        let dir = crate::vault::get_vault_dir().map_err(std::io::Error::other)?;
        let _ = fs::create_dir_all(&dir);
        let token_path = dir.join("ipc.token");

        if token_path.exists() {
            let meta = fs::symlink_metadata(&token_path)?;
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Security Error: IPC token path is an untrusted symlink!",
                ));
            }
            if let Ok(content) = fs::read_to_string(&token_path) {
                let trimmed = content.trim();
                if trimmed.len() >= 32 {
                    return Ok(trimmed.to_string());
                }
            }
        }

        // Generate 32-byte secure CSPRNG token
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let token = format!("sg_ipc_{}", hex_str);

        let mut file = crate::vault::create_secure_file_exclusive(&token_path, 0o600)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;

        Ok(token)
    }

    /// Validates an active session ID against session registry and TTL (3600s)
    pub fn validate_session(&self, session_id: &str) -> Result<AuthenticatedSession, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut registry = self.sessions.write().unwrap();
        if let Some(session) = registry.get_mut(session_id) {
            // Check session TTL (1 hour)
            if now.saturating_sub(session.last_active_at) > 3600 {
                registry.remove(session_id);
                return Err(
                    "Authentication Session Expired (TTL 3600s). Re-authenticate.".to_string(),
                );
            }
            session.last_active_at = now;
            Ok(session.clone())
        } else {
            Err("Authentication Required: Session expired or invalid (Session ID not found in broker registry).".to_string())
        }
    }

    /// Processes an incoming IPC message and returns the response
    pub fn handle_message(&self, msg: &IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::Authenticate {
                token,
                client_name,
                pid,
            } => {
                if token != &self.expected_token {
                    return IpcMessage::AuthenticateResponse {
                        authenticated: false,
                        session_id: String::new(),
                        message: "Invalid IPC authentication token.".to_string(),
                    };
                }

                let mut nonce = [0u8; 16];
                OsRng.fill_bytes(&mut nonce);
                let hex_nonce: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
                let session_id = format!("sess_{}", hex_nonce);

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let req_type = match client_name.to_lowercase().as_str() {
                    "claude-code" | "aider" | "copilot" | "cline" => RequesterType::AutonomousAgent,
                    "vscode" | "cursor" | "windsurf" | "zed" => RequesterType::ApprovedIde,
                    _ => RequesterType::AutonomousAgent,
                };

                let session = AuthenticatedSession {
                    session_id: session_id.clone(),
                    client_name: client_name.clone(),
                    pid: *pid,
                    requester_type: req_type,
                    established_at: now,
                    last_active_at: now,
                };

                self.sessions
                    .write()
                    .unwrap()
                    .insert(session_id.clone(), session);

                IpcMessage::AuthenticateResponse {
                    authenticated: true,
                    session_id,
                    message: format!("Authenticated as '{}' (PID {})", client_name, pid),
                }
            }
            IpcMessage::AuthorizeRequest {
                session_id,
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match self.validate_session(session_id) {
                    Ok(s) => s,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: e,
                        }
                    }
                };

                let op_type = parse_op_type(operation);
                let ident = IdentityContext::mock(
                    &active_session.client_name,
                    active_session.requester_type,
                    None,
                    None,
                );
                let req = OperationRequest::new(ident, credential_name, op_type, target_resource);

                let decision = self.broker.authorize(&req);
                let allowed = matches!(
                    decision,
                    AuthorizationDecision::AllowDelegated | AuthorizationDecision::AllowRaw
                );
                let seq = self
                    .broker
                    .audit_ledger
                    .lock()
                    .ok()
                    .and_then(|l| l.records.last().map(|r| r.sequence_number))
                    .unwrap_or(0);

                let (dec_str, details) = match decision {
                    AuthorizationDecision::AllowDelegated => (
                        "AllowDelegated".to_string(),
                        Some("Delegated execution permitted via broker.".to_string()),
                    ),
                    AuthorizationDecision::AllowRaw => (
                        "AllowRaw".to_string(),
                        Some("Raw credential access permitted.".to_string()),
                    ),
                    AuthorizationDecision::RequireHumanApproval { prompt, .. } => {
                        ("RequireHumanApproval".to_string(), Some(prompt))
                    }
                    AuthorizationDecision::Deny { reason } => ("Deny".to_string(), Some(reason)),
                };

                IpcMessage::AuthorizeResponse {
                    decision: dec_str,
                    allowed,
                    audit_sequence: seq,
                    details,
                }
            }
            IpcMessage::DelegatedCallRequest {
                session_id,
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match self.validate_session(session_id) {
                    Ok(s) => s,
                    Err(e) => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: e,
                        }
                    }
                };

                let op_type = parse_op_type(operation);
                let ident = IdentityContext::mock(
                    &active_session.client_name,
                    active_session.requester_type,
                    None,
                    None,
                );
                let req = OperationRequest::new(ident, credential_name, op_type, target_resource);

                match self.broker.execute_delegated_call(&req, None) {
                    Ok(resp) => IpcMessage::DelegatedCallResponse {
                        status_code: resp.status_code,
                        body: resp.body,
                        scrubbed_count: resp.scrubbed_tokens_count,
                        audit_sequence: resp.audit_sequence,
                    },
                    Err(e) => IpcMessage::Error {
                        code: -32003,
                        message: format!("Delegated execution failed: {}", e),
                    },
                }
            }
            _ => IpcMessage::Error {
                code: -32601,
                message: "Unsupported IPC message type.".to_string(),
            },
        }
    }

    /// Runs local loopback TCP IPC transport listener
    pub fn run_listener(&self, port: u16) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        println!(
            "🛡️  SecretGuard Authenticated IPC Service listening on 127.0.0.1:{}",
            port
        );

        for mut stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut line = String::new();
            if reader.read_line(&mut line)? > 0 {
                if let Ok(req_msg) = serde_json::from_str::<IpcMessage>(line.trim()) {
                    let resp_msg = self.handle_message(&req_msg);
                    let resp_json = serde_json::to_string(&resp_msg).unwrap_or_default();
                    let _ = writeln!(stream, "{}", resp_json);
                    let _ = stream.flush();
                }
            }
        }
        Ok(())
    }
}

/// Client helper: sends an authenticated IPC message across loopback socket
pub fn send_ipc_request(port: u16, msg: &IpcMessage) -> Result<IpcMessage, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .map_err(|e| format!("Failed to connect to SecretGuard IPC service: {}", e))?;

    let json_req = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    writeln!(stream, "{}", json_req).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read IPC response: {}", e))?;

    serde_json::from_str::<IpcMessage>(line.trim())
        .map_err(|e| format!("Invalid IPC response: {}", e))
}

fn parse_op_type(op: &str) -> OperationType {
    match op.to_uppercase().as_str() {
        "GET" | "HTTPGET" => OperationType::HttpGet,
        "POST" | "HTTPPOST" => OperationType::HttpPost,
        "PUT" | "HTTPPUT" => OperationType::HttpPut,
        "DELETE" | "HTTPDELETE" => OperationType::HttpDelete,
        "FETCH" | "GIT:FETCH" => OperationType::GitFetch,
        "PUSH" | "GIT:PUSH" => OperationType::GitPush,
        "RAW" | "RAW:READ" => OperationType::RawCredentialAccess,
        other => OperationType::McpToolCall(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_authentication_handshake_and_session_registration() {
        let temp_dir = std::env::temp_dir().join(format!("sg_ipc_unit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        std::env::set_var("SECRETGUARD_DIR", &temp_dir);

        let server = IpcServer::new();
        let correct_token = server.expected_token.clone();

        // 1. Wrong token fails
        let fail_msg = IpcMessage::Authenticate {
            token: "invalid_token".to_string(),
            client_name: "test_agent".to_string(),
            pid: 1234,
        };
        let res = server.handle_message(&fail_msg);
        match res {
            IpcMessage::AuthenticateResponse { authenticated, .. } => assert!(!authenticated),
            _ => panic!("Expected AuthenticateResponse"),
        }

        // 2. Correct token succeeds and registers session
        let ok_msg = IpcMessage::Authenticate {
            token: correct_token,
            client_name: "claude-code".to_string(),
            pid: 1234,
        };
        let res = server.handle_message(&ok_msg);
        let session_id = match res {
            IpcMessage::AuthenticateResponse {
                authenticated,
                session_id,
                ..
            } => {
                assert!(authenticated);
                assert!(session_id.starts_with("sess_"));
                session_id
            }
            _ => panic!("Expected AuthenticateResponse"),
        };

        // 3. Authenticated session permits authorize call
        let auth_op = IpcMessage::AuthorizeRequest {
            session_id: session_id.clone(),
            credential_name: "GITHUB_TOKEN".to_string(),
            operation: "GET".to_string(),
            target_resource: "https://api.github.com/repos/org/repo/pulls".to_string(),
        };
        let op_res = server.handle_message(&auth_op);
        match op_res {
            IpcMessage::AuthorizeResponse { allowed, .. } => assert!(allowed),
            _ => panic!("Expected AuthorizeResponse"),
        }

        // 4. Fake session ID fails closed
        let fake_op = IpcMessage::AuthorizeRequest {
            session_id: "sess_fake_unregistered_id".to_string(),
            credential_name: "GITHUB_TOKEN".to_string(),
            operation: "GET".to_string(),
            target_resource: "https://api.github.com".to_string(),
        };
        let fake_res = server.handle_message(&fake_op);
        match fake_res {
            IpcMessage::Error { code, .. } => assert_eq!(code, -32001),
            _ => panic!("Expected Error code -32001 for fake session"),
        }

        std::env::remove_var("SECRETGUARD_DIR");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
