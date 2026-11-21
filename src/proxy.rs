use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

pub struct MockProxyServer;

impl MockProxyServer {
    /// Starts a lightweight local mock API server returning realistic provider responses
    pub fn start(bind_addr: &str) -> Result<String, String> {
        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| format!("Failed to bind Mock API Server to {}: {}", bind_addr, e))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| format!("Failed to get local address: {}", e))?;

        let addr_str = local_addr.to_string();

        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let _ = Self::handle_client(stream);
                });
            }
        });

        Ok(addr_str)
    }

    fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
        let mut buffer = [0u8; 4096];
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }

        let req_str = String::from_utf8_lossy(&buffer[..bytes_read]);
        let (status_code, body) = if req_str.contains("/v1/chat/completions") {
            // OpenAI Mock Response
            ("200 OK", r#"{"id":"chatcmpl-mock123","object":"chat.completion","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"[SecretGuard Offline Mock]: Successfully responded without invoking real OpenAI API."},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":15,"total_tokens":25}}"#)
        } else if req_str.contains("/v1/charges") || req_str.contains("/v1/payment_intents") {
            // Stripe Mock Response
            ("200 OK", r#"{"id":"pi_mock123","object":"payment_intent","amount":2000,"currency":"usd","status":"succeeded","client_secret":"pi_mock123_secret_mock"}"#)
        } else {
            // Generic 200 OK
            ("200 OK", r#"{"status":"success","mock":true,"engine":"SecretGuard Offline Mock API"}"#)
        };

        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_code,
            body.len(),
            body
        );

        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }

    /// CLI Handler for `secretguard proxy`
    pub fn run_cli(args: &[String]) {
        let port = if !args.is_empty() && !args[0].starts_with('-') {
            &args[0]
        } else {
            "9090"
        };

        let bind_target = format!("127.0.0.1:{}", port);
        match Self::start(&bind_target) {
            Ok(addr) => {
                println!("🌐 SecretGuard Offline Mock API Proxy active on: \x1b[32mhttp://{}\x1b[0m", addr);
                println!("💡 Point your development SDKs to http://{}:", addr);
                println!("   • OpenAI Base URL: http://{}/v1", addr);
                println!("   • Stripe Base URL: http://{}", addr);
                println!("🛡️ 100% Offline. Zero external network calls. Zero API costs.");
                println!("Press Ctrl+C to stop.");
                loop {
                    thread::park();
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to start mock proxy: {}", e);
                std::process::exit(1);
            }
        }
    }
}
