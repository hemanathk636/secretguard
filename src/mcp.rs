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

pub fn run_mcp_server(engine: &SecretGuardEngine) {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = io::BufReader::new(stdin);
    let mut writer = io::BufWriter::new(stdout);

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
                            "name": "secretguard",
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
                            "name": "scan_secrets",
                            "description": "Scans input text or code for exposed API keys, tokens, private keys, or passwords. Returns detection status and matched pattern names in <15 microseconds.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": {
                                        "type": "string",
                                        "description": "The text, code snippet, or command line to scan for secrets"
                                    }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "redact_secrets",
                            "description": "Scans input text and redacts detected secrets and credentials with safe placeholders, preventing leaks into AI context windows or logs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": {
                                        "type": "string",
                                        "description": "The raw text or log content to sanitize"
                                    }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "scan_path",
                            "description": "Scans a local file or directory path for leaked secrets, tokens, and exposed environment variables.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Relative or absolute file or directory path to inspect"
                                    }
                                },
                                "required": ["path"]
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
                    "scan_secrets" => {
                        let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let res = engine.scan_and_sanitize(text);
                        json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&json!({
                                        "has_secret": res.has_secret,
                                        "matched_rules": res.matched_rules,
                                        "rule_count": res.matched_rules.len()
                                    })).unwrap()
                                }
                            ],
                            "isError": false
                        })
                    }
                    "redact_secrets" => {
                        let text = arguments.get("text").and_then(|v| v.as_str()).unwrap_or("");
                        let res = engine.scan_and_sanitize(text);
                        json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": res.sanitized_text
                                }
                            ],
                            "isError": false
                        })
                    }
                    "scan_path" => {
                        let target_path_str = arguments.get("path").and_then(|v| v.as_str()).unwrap_or(".");
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
                            "content": [
                                {
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&json!({
                                        "target": target_path_str,
                                        "leaks_found": findings.len(),
                                        "findings": findings
                                    })).unwrap()
                                }
                            ],
                            "isError": false
                        })
                    }
                    _ => {
                        json!({
                            "content": [
                                {
                                    "type": "text",
                                    "text": format!("Unknown tool: {}", tool_name)
                                }
                            ],
                            "isError": true
                        })
                    }
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
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let p = entry.path();
        let fname = p.file_name().unwrap_or_default().to_string_lossy();

        if fname == ".git" || fname == "target" || fname == "node_modules" {
            continue;
        }

        if p.is_dir() {
            scan_mcp_directory(&p, engine, findings);
        } else if p.is_file() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() > 1_000_000 {
                    continue;
                }
            }
            if let Ok(content) = fs::read_to_string(&p) {
                for (idx, line) in content.lines().enumerate() {
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
        }
    }
}
