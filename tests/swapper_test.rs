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

#[test]
fn test_swapper_malformed_and_non_http_handling() {
    let swapper = Arc::new(SecretSwapper::new());
    swapper.add_mapping("sk-proj-MOCKSECRET", "sk-live-REALPRODUCTIONKEY");

    let addr = swapper
        .clone()
        .start_local_proxy("127.0.0.1:0")
        .expect("Failed to bind random port");

    // 1. Send garbage non-HTTP binary data
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .write_all(b"\xDE\xAD\xBE\xEF\x00\xFF\xAA\x55")
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("400 Bad Request"));
    assert!(!resp.contains("REALPRODUCTIONKEY"));

    // 2. Immediate zero-byte disconnect should be handled cleanly without panic
    let stream_empty = TcpStream::connect(&addr).unwrap();
    drop(stream_empty);
}

#[test]
fn test_swapper_connect_simulation_and_concurrent_clients() {
    let swapper = Arc::new(SecretSwapper::new());
    swapper.add_mapping("sk-proj-FAKETOKEN", "sk-live-REALTOKEN");

    let addr = swapper
        .clone()
        .start_local_proxy("127.0.0.1:0")
        .expect("Failed to bind random port");

    // 1. Test CONNECT tunnel simulation
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("200 Connection Established"));

    // 2. Concurrent client connections
    let mut handles = Vec::new();
    for _ in 0..10 {
        let target_addr = addr.clone();
        handles.push(std::thread::spawn(move || {
            let mut s = TcpStream::connect(&target_addr).unwrap();
            let req = b"POST /v1/chat HTTP/1.1\r\nAuthorization: Bearer sk-proj-FAKETOKEN\r\n\r\n{\"prompt\":\"hello\"}";
            s.write_all(req).unwrap();
            let mut resp_buf = [0u8; 1024];
            let read_n = s.read(&mut resp_buf).unwrap();
            let r_str = String::from_utf8_lossy(&resp_buf[..read_n]);
            assert!(r_str.contains("200 OK"));
            assert!(r_str.contains("\"swapped_tokens\":1"));
            // Response must never contain real production token
            assert!(!r_str.contains("REALTOKEN"));
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
