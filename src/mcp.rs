use crate::identity::IdentityContext;
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType};
use crate::SecretGuardEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

/// State for the MCP AI Security Gateway connected to verified broker IPC service
struct McpGatewayState {
    pub ipc_server: crate::ipc::IpcServer,
    pub current_session_id: Option<String>,
}

impl McpGatewayState {
    pub fn new() -> Self {
        let ipc_server = crate::ipc::IpcServer::new();
        // Automatically establish authenticated session bound to the OS parent process (e.g. IDE / Agent)
        let parent_pid = crate::identity::get_parent_pid(std::process::id()).ok();
        let effective_pid = parent_pid.unwrap_or_else(std::process::id);
        let auth_val = ipc_server.expected_token.clone();

        let auth_msg = crate::ipc::IpcMessage::Authenticate {
            token: auth_val,
            client_name: "mcp-server".to_string(),
            pid: effective_pid,
        };

        let session_id = match ipc_server.handle_message_with_peer(&auth_msg, Some(effective_pid)) {
            crate::ipc::IpcMessage::AuthenticateResponse {
                authenticated,
                session_id,
                ..
            } if authenticated => Some(session_id),
            _ => None,
        };

        Self {
            ipc_server,
            current_session_id: session_id,
        }
    }
}

pub fn run_mcp_server(engine: &SecretGuardEngine) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = io::BufReader::new(stdin);
    let mut writer = io::BufWriter::new(stdout);
    let state = McpGatewayState::new();

    for line in reader.lines() {
        let line: String = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
                let _ = writeln!(writer, "{}", err_resp);
                let _ = writer.flush();
                continue;
            }
        };

        // Handle notifications (no id)
        if req.id.is_none() {
            if req.method == "notifications/initialized" || req.method == "initialized" {
                // Client acknowledged initialization
            }
            continue;
        }

        let req_id = req.id.clone();

        match req.method.as_str() {
            "initialize" => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "secretguard-security-gateway",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    })),
                    error: None,
                };
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                let _ = writer.flush();
            }
            "ping" => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(json!({})),
                    error: None,
                };
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                let _ = writer.flush();
            }
            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "authorize_operation",
                            "description": "Mediates and authorizes an operation or API access request before executing it.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "credential_name": { "type": "string", "description": "Target credential (e.g. GITHUB_TOKEN, OPENAI_API_KEY)" },
                                    "operation": { "type": "string", "description": "HTTP method (GET, POST, DELETE) or action name" },
                                    "target_resource": { "type": "string", "description": "Target endpoint or URL" }
                                },
                                "required": ["credential_name", "operation", "target_resource"]
                            }
                        },
                        {
                            "name": "execute_delegated_call",
                            "description": "Executes an authorized HTTP API call on behalf of the agent without returning or leaking raw secrets across IPC.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "credential_name": { "type": "string", "description": "Credential to bind in-memory" },
                                    "operation": { "type": "string", "description": "HTTP method (GET, POST)" },
                                    "target_resource": { "type": "string", "description": "Target URL" }
                                },
                                "required": ["credential_name", "operation", "target_resource"]
                            }
                        },
                        {
                            "name": "inspect_call_safety",
                            "description": "Inspects third-party tool call arguments and responses for prompt injections, credential leaks, and data exfiltration.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "tool_name": { "type": "string", "description": "Name of proposed tool" },
                                    "arguments": { "type": "string", "description": "Serialized input arguments" },
                                    "response": { "type": "string", "description": "Optional output response to sanitize" }
                                },
                                "required": ["tool_name", "arguments"]
                            }
                        },
                        {
                            "name": "get_security_posture",
                            "description": "Returns active runtime zero-trust policies, trust tier assessment, and audit ledger integrity.",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "scan_secrets",
                            "description": "Scans input text or code for exposed API keys, tokens, private keys, or passwords in <15 microseconds.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "text": { "type": "string", "description": "Text to scan" } },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "redact_secrets",
                            "description": "Scans input text and redacts detected secrets and credentials with safe placeholders.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "text": { "type": "string", "description": "Raw text to sanitize" } },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "mock_secrets",
                            "description": "Replaces detected secrets with format-preserving synthetic dummy tokens matching exact length and prefix.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "text": { "type": "string", "description": "Text to mock" } },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "scan_path",
                            "description": "Scans a local file or directory path for leaked secrets, tokens, and exposed environment variables.",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "path": { "type": "string", "description": "Path to inspect" } },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "eval_firewall_policy",
                            "description": "Evaluates proposed agent commands against security firewall policies (blocks destructive operations and prompt injections).",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "command": { "type": "string", "description": "Command line to evaluate" } },
                                "required": ["command"]
                            }
                        }
                    ]
                });

                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(tools),
                    error: None,
                };
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                let _ = writer.flush();
            }
            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                let tool_result = match tool_name {
                    "authenticate_client" => {
                        // Security: AI agents must never handle or supply broker tokens directly.
                        // Authentication is established automatically at gateway startup bound to the host process.
                        if let Some(sess_id) = state.current_session_id.as_deref() {
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": format!("SecretGuard MCP Gateway is verified and authenticated (Session ID: {}). AI agents do not require or receive broker tokens.", sess_id)
                                }],
                                "isError": false
                            })
                        } else {
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": "SecretGuard MCP Gateway could not establish verified broker session on startup."
                                }],
                                "isError": true
                            })
                        }
                    }
                    "authorize_operation" => {
                        let session_id = arguments
                            .get("session_id")
                            .and_then(|v| v.as_str())
                            .or(state.current_session_id.as_deref());

                        if let Some(sess_id) = session_id {
                            let cred = arguments
                                .get("credential_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let op_str = arguments
                                .get("operation")
                                .and_then(|v| v.as_str())
                                .unwrap_or("GET");
                            let res_url = arguments
                                .get("target_resource")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let auth_req = crate::ipc::IpcMessage::AuthorizeRequest {
                                session_id: sess_id.to_string(),
                                credential_name: cred.to_string(),
                                operation: op_str.to_string(),
                                target_resource: res_url.to_string(),
                            };

                            match state.ipc_server.handle_message(&auth_req) {
                                crate::ipc::IpcMessage::AuthorizeResponse {
                                    decision,
                                    allowed,
                                    audit_sequence,
                                    details,
                                } => json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&json!({
                                            "allowed": allowed,
                                            "decision": decision,
                                            "audit_sequence": audit_sequence,
                                            "details": details,
                                            "credential": cred,
                                            "operation": op_str,
                                            "target": res_url
                                        })).unwrap()
                                    }],
                                    "isError": !allowed
                                }),
                                crate::ipc::IpcMessage::Error { code, message } => json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Security Error [{}]: {}", code, message)
                                    }],
                                    "isError": true
                                }),
                                _ => json!({
                                    "content": [{ "type": "text", "text": "Unexpected broker response" }],
                                    "isError": true
                                }),
                            }
                        } else {
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": "Security Violation: MCP client is unauthenticated. You must call 'authenticate_client' with a valid SecretGuard broker token first.".to_string()
                                }],
                                "isError": true
                            })
                        }
                    }
                    "execute_delegated_call" => {
                        let session_id = arguments
                            .get("session_id")
                            .and_then(|v| v.as_str())
                            .or(state.current_session_id.as_deref());

                        if let Some(sess_id) = session_id {
                            let cred = arguments
                                .get("credential_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let op_str = arguments
                                .get("operation")
                                .and_then(|v| v.as_str())
                                .unwrap_or("GET");
                            let res_url = arguments
                                .get("target_resource")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            let call_req = crate::ipc::IpcMessage::DelegatedCallRequest {
                                session_id: sess_id.to_string(),
                                credential_name: cred.to_string(),
                                operation: op_str.to_string(),
                                target_resource: res_url.to_string(),
                            };

                            match state.ipc_server.handle_message(&call_req) {
                                crate::ipc::IpcMessage::DelegatedCallResponse {
                                    status_code,
                                    body,
                                    scrubbed_count,
                                    audit_sequence,
                                } => json!({
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&json!({
                                            "status_code": status_code,
                                            "body": String::from_utf8_lossy(&body),
                                            "scrubbed_tokens_count": scrubbed_count,
                                            "audit_sequence": audit_sequence
                                        })).unwrap()
                                    }],
                                    "isError": status_code >= 400
                                }),
                                crate::ipc::IpcMessage::Error { code, message } => json!({
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Delegated execution error [{}]: {}", code, message)
                                    }],
                                    "isError": true
                                }),
                                _ => json!({
                                    "content": [{ "type": "text", "text": "Unexpected broker response" }],
                                    "isError": true
                                }),
                            }
                        } else {
                            json!({
                                "content": [{
                                    "type": "text",
                                    "text": "Security Violation: MCP client is unauthenticated. You must call 'authenticate_client' with a valid SecretGuard broker token first.".to_string()
                                }],
                                "isError": true
                            })
                        }
                    }
                    "inspect_call_safety" => {
                        let tool = arguments
                            .get("tool_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let raw_args = arguments
                            .get("arguments")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let raw_resp = arguments
                            .get("response")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let scan_in = engine.scan_and_sanitize(raw_args);
                        let scan_out = engine.scan_and_sanitize(raw_resp);

                        let prompt_injection = raw_args
                            .to_lowercase()
                            .contains("ignore all previous instructions")
                            || raw_args.to_lowercase().contains("system prompt override");

                        let is_safe =
                            !scan_in.has_secret && !scan_out.has_secret && !prompt_injection;

                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "tool": tool,
                                    "safe": is_safe,
                                    "arguments_leaked_secrets": scan_in.has_secret,
                                    "response_leaked_secrets": scan_out.has_secret,
                                    "prompt_injection_detected": prompt_injection,
                                    "sanitized_arguments": scan_in.sanitized_text,
                                    "sanitized_response": scan_out.sanitized_text
                                })).unwrap()
                            }],
                            "isError": !is_safe
                        })
                    }
                    "get_security_posture" => {
                        let policies = state.ipc_server.broker.policy_engine.read().unwrap();
                        let ledger = state.ipc_server.broker.audit_ledger.lock().unwrap();

                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "active_policy_rules": policies.rules.len(),
                                    "audit_records_count": ledger.records.len(),
                                    "ledger_integrity": if ledger.verify_integrity().is_ok() { "Verified" } else { "Uninitialized/Error" }
                                })).unwrap()
                            }],
                            "isError": false
                        })
                    }
                    "scan_secrets" => {
                        let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let res = engine.scan_and_sanitize(text);
                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "has_secret": res.has_secret,
                                    "matched_rules": res.matched_rules,
                                    "rule_count": res.matched_rules.len()
                                })).unwrap()
                            }],
                            "isError": false
                        })
                    }
                    "redact_secrets" => {
                        let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let res = engine.scan_and_sanitize(text);
                        json!({
                            "content": [{ "type": "text", "text": res.sanitized_text }],
                            "isError": false
                        })
                    }
                    "mock_secrets" => {
                        let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let res = engine.scan_and_sanitize(text);
                        json!({
                            "content": [{ "type": "text", "text": res.synthetic_text }],
                            "isError": false
                        })
                    }
                    "scan_path" => {
                        let target_path_str = arguments
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or(".");
                        let path = Path::new(target_path_str);
                        let mut findings = Vec::new();

                        if path.is_file() {
                            if let Ok(content) = fs::read_to_string(path) {
                                for (idx, line) in content.lines().enumerate() {
                                    let res = engine.scan_and_sanitize(line);
                                    if res.has_secret {
                                        findings.push(json!({
                                            "file": target_path_str,
                                            "line": idx + 1,
                                            "rules": res.matched_rules,
                                            "redacted": res.sanitized_text.trim()
                                        }));
                                    }
                                }
                            }
                        } else if path.is_dir() {
                            scan_mcp_directory(path, engine, &mut findings);
                        } else {
                            findings.push(json!({
                                "error": format!("Path does not exist: {}", target_path_str)
                            }));
                        }

                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "target": target_path_str,
                                    "leaks_found": findings.len(),
                                    "findings": findings
                                })).unwrap()
                            }],
                            "isError": false
                        })
                    }
                    "eval_firewall_policy" => {
                        let cmd = arguments
                            .get("command")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let verdict = crate::firewall::evaluate_firewall_command(cmd);

                        // Also audit this evaluation
                        if let Ok(mut ledger) = crate::audit::AuditLedger::load(None) {
                            let ident = IdentityContext::current();
                            let req = OperationRequest::new(
                                ident,
                                "TERMINAL_COMMAND",
                                OperationType::McpToolCall("eval_firewall_policy".to_string()),
                                cmd,
                            );
                            let decision = if verdict.allowed {
                                AuthorizationDecision::AllowRaw
                            } else {
                                AuthorizationDecision::Deny {
                                    reason: format!("Firewall Block: {:?}", verdict.reasons),
                                }
                            };
                            let _ = ledger.record_decision(&req, &decision);
                            let _ = ledger.save(None);
                        }

                        json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&json!({
                                    "command": cmd,
                                    "allowed": verdict.allowed,
                                    "risk_level": format!("{:?}", verdict.risk_level),
                                    "reasons": verdict.reasons
                                })).unwrap()
                            }],
                            "isError": !verdict.allowed
                        })
                    }
                    _ => json!({
                        "content": [{ "type": "text", "text": format!("Unknown tool: {}", tool_name) }],
                        "isError": true
                    }),
                };

                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(tool_result),
                    error: None,
                };
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                let _ = writer.flush();
            }
            _ => {
                let resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: None,
                    error: Some(json!({
                        "code": -32601,
                        "message": format!("Method not found: {}", req.method)
                    })),
                };
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                let _ = writer.flush();
            }
        }
    }
}

fn scan_mcp_directory(dir: &Path, engine: &SecretGuardEngine, findings: &mut Vec<Value>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            findings.push(json!({
                "directory": dir.to_string_lossy(),
                "error": format!("Failed to read directory: {}", e)
            }));
            return;
        }
    };

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                findings.push(json!({
                    "directory": dir.to_string_lossy(),
                    "error": format!("Failed to read entry: {}", e)
                }));
                continue;
            }
        };

        let p = entry.path();
        let fname = p.file_name().unwrap_or_default().to_string_lossy();

        if fname == ".git" || fname == "target" || fname == "node_modules" {
            continue;
        }

        let meta = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                findings.push(json!({
                    "file": p.to_string_lossy(),
                    "error": format!("Failed to inspect metadata: {}", e)
                }));
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            continue; // Refuse to follow symlinks
        }

        if meta.is_dir() {
            scan_mcp_directory(&p, engine, findings);
        } else if meta.is_file() {
            if meta.len() > 1_000_000 {
                continue;
            }
            match fs::read(&p) {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    for (idx, line) in text.lines().enumerate() {
                        let res = engine.scan_and_sanitize(line);
                        if res.has_secret {
                            findings.push(json!({
                                "file": p.to_string_lossy(),
                                "line": idx + 1,
                                "rules": res.matched_rules,
                                "redacted": res.sanitized_text.trim()
                            }));
                        }
                    }
                }
                Err(e) => {
                    findings.push(json!({
                        "file": p.to_string_lossy(),
                        "error": format!("Failed to read file: {}", e)
                    }));
                }
            }
        }
    }
}
