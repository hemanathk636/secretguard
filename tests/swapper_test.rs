use secretguard::swapper::{SecretSwapper, SwapperConfig};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[test]
fn test_swapper_payload_rewriting() {
    let mut config = SwapperConfig::default();
    config.mappings.insert(
        "sk-proj-FAKE000000000000".to_string(),
        "sk-test-REAL1234567890".to_string(),
    );

    let raw_req =
        b"POST /v1/chat HTTP/1.1\r\nAuthorization: Bearer sk-proj-FAKE000000000000\r\n\r\n{}";
    let (swapped_req, count) = SecretSwapper::swap_request_payload(raw_req, &config);
    assert_eq!(count, 1);
    let swapped_str = String::from_utf8(swapped_req).unwrap();
    assert!(swapped_str.contains("sk-test-REAL1234567890"));
    assert!(!swapped_str.contains("sk-proj-FAKE000000000000"));

    // Verify reverse response stripping (real key stripped back to mock)
    let raw_res = b"HTTP/1.1 200 OK\r\n\r\n{\"key\":\"sk-test-REAL1234567890\"}";
    let (stripped_res, strip_count) = SecretSwapper::swap_response_payload(raw_res, &config);
    assert_eq!(strip_count, 1);
    let stripped_str = String::from_utf8(stripped_res).unwrap();
    assert!(stripped_str.contains("sk-proj-FAKE000000000000"));
    assert!(!stripped_str.contains("sk-test-REAL1234567890"));
}

#[test]
fn test_swapper_tcp_proxy_relay() {
    let swapper = Arc::new(SecretSwapper::new());
    swapper.add_mapping("sk-proj-FAKETOKEN", "sk-test-REALTOKEN");

    let addr = swapper
        .clone()
        .start_local_proxy("127.0.0.1:0")
        .expect("Failed to bind random port");

    let mut stream = TcpStream::connect(&addr).expect("Failed to connect to swapper proxy");
    let req = b"GET /status HTTP/1.1\r\nAuthorization: Bearer sk-proj-FAKETOKEN\r\n\r\n";
    stream.write_all(req).unwrap();

    let mut resp = Vec::new();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    resp.extend_from_slice(&buf[..n]);

    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("swapped"));
}
