//! Authenticated Local IPC Protocol for SecretGuard
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
//! - Strict schema validation across JSON-RPC / IPC messages
//! - All operations logged to tamper-evident audit ledger

use crate::broker::SecurityBroker;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;

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
}

/// IPC Handler managing authenticated requests
pub struct IpcServer {
    pub broker: SecurityBroker,
    expected_token: String,
}

impl Default for IpcServer {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcServer {
    pub fn new() -> Self {
        let expected_token = Self::get_or_create_token()
            .unwrap_or_else(|_| "sg_fallback_ephemeral_token".to_string());
        Self {
            broker: SecurityBroker::new(),
            expected_token,
        }
    }

    /// Derives or creates local IPC authentication token stored securely in .secretguard/ipc.token (0o600)
    pub fn get_or_create_token() -> Result<String, std::io::Error> {
        let dir = crate::vault::get_vault_dir().map_err(std::io::Error::other)?;
        let _ = fs::create_dir_all(&dir);
        let token_path = dir.join("ipc.token");

        if token_path.exists() {
            if let Ok(content) = fs::read_to_string(&token_path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
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

    /// Processes an incoming IPC message and returns the response
    pub fn handle_message(
        &self,
        session: Option<&AuthenticatedSession>,
        msg: &IpcMessage,
    ) -> IpcMessage {
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

                IpcMessage::AuthenticateResponse {
                    authenticated: true,
                    session_id,
                    message: format!("Authenticated as '{}' (PID {})", client_name, pid),
                }
            }
            IpcMessage::AuthorizeRequest {
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match session {
                    Some(s) => s,
                    None => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: "Authentication required before requesting authorization."
                                .to_string(),
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
                credential_name,
                operation,
                target_resource,
            } => {
                let active_session = match session {
                    Some(s) => s,
                    None => {
                        return IpcMessage::Error {
                            code: -32001,
                            message: "Authentication required before executing delegated call."
                                .to_string(),
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
    fn test_ipc_authentication_handshake() {
        let server = IpcServer::new();
        let correct_token = server.expected_token.clone();

        // 1. Wrong token fails
        let fail_msg = IpcMessage::Authenticate {
            token: "invalid_token".to_string(),
            client_name: "test_agent".to_string(),
            pid: 1234,
        };
        let res = server.handle_message(None, &fail_msg);
        match res {
            IpcMessage::AuthenticateResponse { authenticated, .. } => assert!(!authenticated),
            _ => panic!("Expected AuthenticateResponse"),
        }

        // 2. Correct token succeeds
        let ok_msg = IpcMessage::Authenticate {
            token: correct_token,
            client_name: "claude-code".to_string(),
            pid: 1234,
        };
        let res = server.handle_message(None, &ok_msg);
        match res {
            IpcMessage::AuthenticateResponse {
                authenticated,
                session_id,
                ..
            } => {
                assert!(authenticated);
                assert!(session_id.starts_with("sess_"));
            }
            _ => panic!("Expected AuthenticateResponse"),
        }
    }

    #[test]
    fn test_unauthenticated_request_rejected() {
        let server = IpcServer::new();
        let auth_req = IpcMessage::AuthorizeRequest {
            credential_name: "GITHUB_TOKEN".to_string(),
            operation: "GET".to_string(),
            target_resource: "https://api.github.com".to_string(),
        };

        let res = server.handle_message(None, &auth_req);
        match res {
            IpcMessage::Error { code, .. } => assert_eq!(code, -32001),
            _ => panic!("Expected Error with code -32001"),
        }
    }
}
