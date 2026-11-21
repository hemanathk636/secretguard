use secretguard::proxy::MockProxyServer;
use std::io::{Read, Write};
use std::net::TcpStream;

#[test]
fn test_offline_mock_openai_response() {
    let addr = MockProxyServer::start("127.0.0.1:0").expect("Failed to bind random port");

    let mut stream = TcpStream::connect(&addr).expect("Failed to connect");
    let req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n\r\n{}";
    stream.write_all(req).unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("HTTP/1.1 200 OK"));
    assert!(resp.contains("chatcmpl-mock123"));
    assert!(resp.contains("[SecretGuard Offline Mock]"));
}

#[test]
fn test_offline_mock_stripe_response() {
    let addr = MockProxyServer::start("127.0.0.1:0").expect("Failed to bind random port");

    let mut stream = TcpStream::connect(&addr).expect("Failed to connect");
    let req = b"POST /v1/payment_intents HTTP/1.1\r\nHost: localhost\r\n\r\n{}";
    stream.write_all(req).unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("HTTP/1.1 200 OK"));
    assert!(resp.contains("pi_mock123"));
}
