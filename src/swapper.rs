//! SecretSwapper - Experimental Local Developer Simulation Testbed
//!
//! Note on Scope: `secretguard tun` is a local developer simulation prototype for testing
//! synthetic mock token substitution in development and CI environments. It operates as
//! an HTTP mock/relay endpoint for developers testing AI agent workflows without real
//! credentials. It is NOT a production-grade TLS reverse proxy and does not perform
//! in-flight TLS interception or dynamic certificate authority signing.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Configuration mapping synthetic mock tokens to real secrets for local simulation
#[derive(Debug, Clone, Default)]
pub struct SwapperConfig {
    /// Maps mock token (e.g. "sk-proj-FAKETEST...") -> real token (e.g. "sk-proj-REAL...")
    pub mappings: HashMap<String, String>,
}

/// Experimental local developer simulation testbed for token substitution
pub struct SecretSwapper {
    config: Arc<Mutex<SwapperConfig>>,
}

impl SecretSwapper {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(SwapperConfig::default())),
        }
    }

    /// Add a mock-to-real token mapping
    pub fn add_mapping(&self, mock_token: &str, real_token: &str) {
        if let Ok(mut cfg) = self.config.lock() {
            cfg.mappings
                .insert(mock_token.to_string(), real_token.to_string());
        }
    }

    /// Rewrites an HTTP request buffer by replacing synthetic mock tokens with real tokens
    pub fn swap_request_payload(payload: &[u8], config: &SwapperConfig) -> (Vec<u8>, usize) {
        let mut text = String::from_utf8_lossy(payload).to_string();
        let mut replacements = 0;

        for (mock, real) in &config.mappings {
            if text.contains(mock) {
                text = text.replace(mock, real);
                replacements += 1;
            }
        }

        (text.into_bytes(), replacements)
    }

    /// Rewrites an HTTP response buffer by stripping/redacting any accidental leaks of the real token back to mock
    pub fn swap_response_payload(payload: &[u8], config: &SwapperConfig) -> (Vec<u8>, usize) {
        let mut text = String::from_utf8_lossy(payload).to_string();
        let mut replacements = 0;

        for (mock, real) in &config.mappings {
            if text.contains(real) {
                text = text.replace(real, mock);
                replacements += 1;
            }
        }

        (text.into_bytes(), replacements)
    }

    /// Start a local proxy listener on specified port (simulation testbed)
    pub fn start_local_proxy(self: Arc<Self>, bind_addr: &str) -> Result<String, String> {
        let listener = TcpListener::bind(bind_addr).map_err(|e| {
            format!(
                "Failed to bind local simulation swapper to {}: {}",
                bind_addr, e
            )
        })?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to read local address: {}", e))?;

        let addr_str = local_addr.to_string();

        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let swapper = Arc::clone(&self);
                thread::spawn(move || {
                    let _ = swapper.handle_client(stream);
                });
            }
        });

        Ok(addr_str)
    }

    fn handle_client(&self, mut client_stream: TcpStream) -> std::io::Result<()> {
        let mut buffer = [0u8; 8192];
        let bytes_read = client_stream.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }

        let cfg = self.config.lock().unwrap().clone();
        let (rewritten_req, swapped_count) =
            Self::swap_request_payload(&buffer[..bytes_read], &cfg);

        // Simple local HTTP mock or relay acknowledgment for zero-cloud testing
        let req_str = String::from_utf8_lossy(&rewritten_req);
        if req_str.starts_with("CONNECT ") {
            // HTTPS Tunnel establish simulation response
            let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            client_stream.write_all(response.as_bytes())?;
        } else {
            // Standard HTTP intercepted relay
            let response_body = format!(
                r#"{{"status":"swapped","swapped_tokens":{},"simulation":true,"message":"SecretGuard Local Swapper [Simulation]: Mock tokens substituted for local testing."}}"#,
                swapped_count
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            client_stream.write_all(response.as_bytes())?;
        }

        client_stream.flush()?;
        Ok(())
    }

    /// CLI Handler for `secretguard tun`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard tun [EXPERIMENTAL] - Local Developer Token Swapper Simulation Testbed

Notice: This command provides a lightweight local simulation testbed for validating
credential substitution workflows during development and automated CI testing.
It is an experimental developer utility, NOT a production-grade TLS reverse proxy.

USAGE:
    secretguard tun <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    start [--port 8080] [--map MOCK=REAL...]  Starts local simulation proxy listener
    swap "<TEXT>" [--map MOCK=REAL...]        Simulates payload swapping on input text
"#
            );
            return;
        }

        match args[0].as_str() {
            "swap" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard tun swap \"<PAYLOAD>\" [--map MOCK=REAL...]");
                    std::process::exit(2);
                }
                let payload = &args[1];
                let mut cfg = SwapperConfig::default();

                let mut i = 2;
                while i < args.len() {
                    if args[i] == "--map" && i + 1 < args.len() {
                        let mapping = &args[i + 1];
                        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            cfg.mappings
                                .insert(parts[0].to_string(), parts[1].to_string());
                        }
                        i += 2;
                    } else if let Some(stripped) = args[i].strip_prefix("--map=") {
                        let parts: Vec<&str> = stripped.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            cfg.mappings
                                .insert(parts[0].to_string(), parts[1].to_string());
                        }
                        i += 1;
                    } else {
                        i += 1;
                    }
                }

                let (swapped, count) = Self::swap_request_payload(payload.as_bytes(), &cfg);
                println!("🔄 Swapped {} secret tokens in simulation payload:", count);
                println!("{}", String::from_utf8_lossy(&swapped));
            }
            "start" => {
                let mut port = "8080";
                let swapper = Arc::new(Self::new());

                let mut i = 1;
                while i < args.len() {
                    if args[i] == "--port" && i + 1 < args.len() {
                        port = &args[i + 1];
                        i += 2;
                    } else if args[i] == "--map" && i + 1 < args.len() {
                        let mapping = &args[i + 1];
                        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            swapper.add_mapping(parts[0], parts[1]);
                        }
                        i += 2;
                    } else if let Some(stripped) = args[i].strip_prefix("--map=") {
                        let parts: Vec<&str> = stripped.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            swapper.add_mapping(parts[0], parts[1]);
                        }
                        i += 1;
                    } else {
                        i += 1;
                    }
                }

                let bind_target = format!("127.0.0.1:{}", port);
                match swapper.clone().start_local_proxy(&bind_target) {
                    Ok(addr) => {
                        println!("🧪 SecretGuard Local Swapper [Simulation Prototype] listening on: \x1b[32mhttp://{}\x1b[0m", addr);
                        println!(
                            "💡 Configure HTTP_PROXY=http://{} for local test environments.",
                            addr
                        );
                        println!("⚠️  Note: This simulation testbed is for development workflows, not production TLS interception.");
                        println!("Press Ctrl+C to stop.");
                        loop {
                            thread::park();
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to start secret swapper: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!("Unknown subcommand: {}. Use 'start' or 'swap'.", args[0]);
                std::process::exit(2);
            }
        }
    }
}

impl Default for SecretSwapper {
    fn default() -> Self {
        Self::new()
    }
}
