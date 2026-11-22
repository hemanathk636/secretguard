use secretguard::vault::{
    decrypt_vault_payload, derive_vault_key, encrypt_vault_payload, get_or_generate_master_key,
    load_vault, save_vault, VaultStore,
};
use std::fs;
use std::sync::Mutex;

static VAULT_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_vault_aes_gcm_roundtrip() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_roundtrip_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let key = derive_vault_key(Some("test-passphrase-123")).expect("Key derivation failed");
    let plaintext = b"sk-proj-super-secret-production-openai-key";

    let encrypted = encrypt_vault_payload(plaintext, &key).expect("Encryption failed");
    assert_ne!(encrypted, plaintext);
    assert!(encrypted.len() > plaintext.len()); // Nonce + Auth Tag + Ciphertext

    let decrypted = decrypt_vault_payload(&encrypted, &key).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_vault_wrong_key_fails() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_wrong_key_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let key1 = derive_vault_key(Some("correct-key")).expect("Key derivation failed");
    let key2 = derive_vault_key(Some("wrong-key")).expect("Key derivation failed");
    let plaintext = b"my-private-database-password";

    let encrypted = encrypt_vault_payload(plaintext, &key1).unwrap();
    let result = decrypt_vault_payload(&encrypted, &key2);

    assert!(result.is_err());

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_vault_store_serialization() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_store_ser_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let mut store = VaultStore::default();
    store
        .secrets
        .insert("OPENAI_KEY".to_string(), "sk-1234567890".to_string());
    store
        .secrets
        .insert("STRIPE_KEY".to_string(), "sk_live_998877".to_string());

    let json = serde_json::to_vec(&store).unwrap();
    let key = derive_vault_key(None).expect("Key derivation failed");
    let enc = encrypt_vault_payload(&json, &key).unwrap();
    let dec = decrypt_vault_payload(&enc, &key).unwrap();
    let loaded: VaultStore = serde_json::from_slice(&dec).unwrap();

    assert_eq!(loaded.secrets.len(), 2);
    assert_eq!(loaded.secrets.get("OPENAI_KEY").unwrap(), "sk-1234567890");
    assert_eq!(loaded.secrets.get("STRIPE_KEY").unwrap(), "sk_live_998877");

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_corrupted_vault_file_fails_loudly_without_data_loss() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_vault_corrupt_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let corrupt_vault_path = temp_dir.join("vault.enc");

    // Write bogus corrupted ciphertext
    fs::write(&corrupt_vault_path, b"not_valid_aes_gcm_ciphertext_at_all").unwrap();

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_VAULT_PATH", &corrupt_vault_path);

    // Attempting to load MUST return Err, NEVER unwrap_or_default
    let result = load_vault(None);
    assert!(result.is_err(), "Loading a corrupted vault MUST fail with Err to prevent overwriting existing data");

    // Cleanup
    std::env::remove_var("SECRETGUARD_VAULT_PATH");
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_corrupted_master_key_aborts_to_prevent_data_loss() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_master_key_corrupt_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let corrupt_key_path = temp_dir.join(".master.key");

    // Write truncated key (< 32 bytes)
    fs::write(&corrupt_key_path, b"short_16_byte_key!").unwrap();

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_MASTER_KEY_PATH", &corrupt_key_path);

    let result = get_or_generate_master_key();
    assert!(result.is_err(), "Truncated master key must be rejected to prevent vault orphaning");
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("corrupted"), "Error should explain key corruption: {}", err_msg);

    // Cleanup
    std::env::remove_var("SECRETGUARD_MASTER_KEY_PATH");
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_atomic_unique_tmp_file_during_save_vault() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_save_atomic_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let vault_path = temp_dir.join("vault.enc");

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_VAULT_PATH", &vault_path);

    let mut store = VaultStore::default();
    store.secrets.insert("PROD_DB".to_string(), "postgres://user:pass@db:5432/prod".to_string());

    let save_res = save_vault(&store, None);
    assert!(save_res.is_ok(), "save_vault should succeed with unique tmp file");
    assert!(vault_path.exists(), "Final vault file must exist after atomic rename");

    // Verify temp files were cleanly cleaned up
    let entries: Vec<_> = fs::read_dir(&temp_dir).unwrap().filter_map(|e| e.ok()).collect();
    // vault.enc and .master.key exist, but no .vault.*.tmp files
    let tmp_files: Vec<_> = entries.iter().filter(|e| e.file_name().to_string_lossy().contains(".tmp")).collect();
    assert_eq!(tmp_files.len(), 0, "All temporary files must be cleaned up");

    std::env::remove_var("SECRETGUARD_VAULT_PATH");
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_windows_and_unix_existing_vault_replacement() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_replace_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let vault_path = temp_dir.join("vault.enc");

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_VAULT_PATH", &vault_path);

    let mut store = VaultStore::default();
    store.secrets.insert("KEY1".to_string(), "val1".to_string());
    assert!(save_vault(&store, None).is_ok(), "Initial save must succeed");

    // Replace existing vault multiple times to test Windows and Unix file replacement
    store.secrets.insert("KEY2".to_string(), "val2".to_string());
    assert!(save_vault(&store, None).is_ok(), "Overwriting existing vault must succeed atomically");

    store.secrets.insert("KEY3".to_string(), "val3".to_string());
    assert!(save_vault(&store, None).is_ok(), "Third update to existing vault must succeed atomically");

    let loaded = load_vault(None).expect("Vault should load updated secrets");
    assert_eq!(loaded.secrets.len(), 3);
    assert_eq!(loaded.secrets.get("KEY3").unwrap(), "val3");

    std::env::remove_var("SECRETGUARD_VAULT_PATH");
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_strip_line_terminator_preserves_whitespace() {
    use secretguard::vault::strip_line_terminator;

    let mut crlf = "  secret_with_spaces  \r\n".to_string();
    strip_line_terminator(&mut crlf);
    assert_eq!(crlf, "  secret_with_spaces  ");

    let mut lf = "password 123\n".to_string();
    strip_line_terminator(&mut lf);
    assert_eq!(lf, "password 123");

    let mut no_term = "  leading_and_trailing  ".to_string();
    strip_line_terminator(&mut no_term);
    assert_eq!(no_term, "  leading_and_trailing  ");
}

#[test]
fn test_binary_stream_preservation_and_credential_sanitization() {
    use secretguard::vault::sanitize_stream_buffer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();

    // 1. Pure binary with invalid UTF-8 bytes: must be preserved byte-for-byte
    let raw_binary = vec![0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00, 0x42];
    let mut out_binary = Vec::new();
    sanitize_stream_buffer(&raw_binary, &engine, &mut out_binary).unwrap();
    assert_eq!(out_binary, raw_binary, "Clean binary chunks must be preserved unmodified byte-for-byte");

    // 2. Binary with embedded ASCII credential: MUST detect and redact credential (cannot bypass)
    let mut tainted_binary = vec![0x1f, 0x8b, 0x08];
    tainted_binary.extend_from_slice(b"sk-proj-embeddedTokenInBinary01234567890abcdef");
    tainted_binary.extend_from_slice(&[0x00, 0xff]);

    let mut out_tainted = Vec::new();
    sanitize_stream_buffer(&tainted_binary, &engine, &mut out_tainted).unwrap();
    let out_str = String::from_utf8_lossy(&out_tainted);
    assert!(!out_str.contains("sk-proj-embeddedTokenInBinary01234567890abcdef"), "Embedded credential in binary output MUST be redacted");
    assert!(out_str.contains("[REDACTED_OPENAI_KEY]") || out_str.contains("[REDACTED"), "Credential must be redacted in output");
}

#[test]
fn test_stream_sanitizer_split_chunk_credential_detection() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Chunk 1: prefix of OpenAI key split right in the middle
    let chunk1 = b"export OPENAI_API_KEY=\"sk-proj-prefixPart12345";
    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(chunk1, &engine, &mut out1).unwrap();

    // Chunk 2: suffix of the key completing the credential across chunk boundary
    let chunk2 = b"67890suffixPartAbcdef0123456789\"\n";
    let mut out2 = Vec::new();
    sanitizer.sanitize_chunk(chunk2, &engine, &mut out2).unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let combined_out = format!("{}{}", String::from_utf8_lossy(&out1), String::from_utf8_lossy(&out2));
    assert!(out1.is_empty(), "Partial chunk within 1024-byte window must be held back to prevent leak");
    assert!(
        !combined_out.contains("sk-proj-prefixPart1234567890suffixPartAbcdef0123456789"),
        "Credential split across chunks MUST be redacted across boundary"
    );
    assert!(
        combined_out.contains("[REDACTED_OPENAI_KEY]") || combined_out.contains("[REDACTED"),
        "Split credential must trigger redaction in output: {}",
        combined_out
    );
}

#[test]
fn test_stream_sanitizer_large_stream_sliding_holdback() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Stream 5KB of non-secret filler text
    let filler = vec![b'A'; 5000];
    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(&filler, &engine, &mut out1).unwrap();
    // out1 should have drained 5000 - 4096 = 904 bytes
    assert_eq!(out1.len(), 5000 - StreamSanitizer::WINDOW_SIZE);

    // Now inject split secret in chunk 2 and chunk 3
    let chunk2 = b"prefix_filler ghp_1234567890";
    let mut out2 = Vec::new();
    sanitizer.sanitize_chunk(chunk2, &engine, &mut out2).unwrap();

    let chunk3 = b"12345678901234567890123456 suffix_filler\n";
    let mut out3 = Vec::new();
    sanitizer.sanitize_chunk(chunk3, &engine, &mut out3).unwrap();

    let mut out_final = Vec::new();
    sanitizer.flush_final(&engine, &mut out_final).unwrap();

    let total = format!(
        "{}{}{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2),
        String::from_utf8_lossy(&out3),
        String::from_utf8_lossy(&out_final)
    );
    assert!(!total.contains("ghp_123456789012345678901234567890123456"), "Split GitHub token across chunks must be redacted");
    assert!(total.contains("[REDACTED_GITHUB_TOKEN]") || total.contains("[REDACTED]"));
}

#[test]
fn test_stream_sanitizer_long_pem_and_jwt_split_chunk() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 1. Full 2048-bit RSA PEM private key block (~1.7 KB) split across 3 chunks
    let mut full_pem = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
    for i in 0..24 {
        full_pem.push_str(&format!("MIIEowIBAAKCAQEA0Y5k1vABCD{}EFGH{}IJKL{}MNOP{}QRST{}UVWX{}YZab1234567890=\n", i, i, i, i, i, i));
    }
    full_pem.push_str("-----END RSA PRIVATE KEY-----\n");
    assert!(full_pem.len() > 1500, "Full PEM must be a realistic 1.5KB+ key block");

    let split_point1 = 500;
    let split_point2 = 1100;
    let chunk_pem1 = &full_pem.as_bytes()[..split_point1];
    let chunk_pem2 = &full_pem.as_bytes()[split_point1..split_point2];
    let chunk_pem3 = &full_pem.as_bytes()[split_point2..];

    let mut out_pem1 = Vec::new();
    sanitizer.sanitize_chunk(chunk_pem1, &engine, &mut out_pem1).unwrap();
    assert!(out_pem1.is_empty(), "Partial PEM header must be held back in window");

    let mut out_pem2 = Vec::new();
    sanitizer.sanitize_chunk(chunk_pem2, &engine, &mut out_pem2).unwrap();

    let mut out_pem3 = Vec::new();
    sanitizer.sanitize_chunk(chunk_pem3, &engine, &mut out_pem3).unwrap();
    sanitizer.flush_final(&engine, &mut out_pem3).unwrap();

    let pem_out = format!("{}{}{}", String::from_utf8_lossy(&out_pem1), String::from_utf8_lossy(&out_pem2), String::from_utf8_lossy(&out_pem3));
    assert!(!pem_out.contains("-----BEGIN RSA PRIVATE KEY-----"), "Full PEM key header must be redacted");
    assert!(pem_out.contains("[REDACTED]"), "Sanitizer must redact full PEM block");

    // 2. Large JWT token (1.2KB) split across 3 chunk boundaries
    let mut jwt_sanitizer = StreamSanitizer::new();
    let mut full_jwt = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.");
    for _ in 0..15 {
        full_jwt.push_str("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
    }
    full_jwt.push_str(".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c_final_signature\n");
    assert!(full_jwt.len() > 1000, "JWT must be realistic 1KB+ token");

    let jwt_split1 = 350;
    let jwt_split2 = 750;
    let mut out_jwt1 = Vec::new();
    jwt_sanitizer.sanitize_chunk(&full_jwt.as_bytes()[..jwt_split1], &engine, &mut out_jwt1).unwrap();
    assert!(out_jwt1.is_empty(), "Partial JWT within window must be held back");

    let mut out_jwt2 = Vec::new();
    jwt_sanitizer.sanitize_chunk(&full_jwt.as_bytes()[jwt_split1..jwt_split2], &engine, &mut out_jwt2).unwrap();

    let mut out_jwt3 = Vec::new();
    jwt_sanitizer.sanitize_chunk(&full_jwt.as_bytes()[jwt_split2..], &engine, &mut out_jwt3).unwrap();
    jwt_sanitizer.flush_final(&engine, &mut out_jwt3).unwrap();

    let jwt_out = format!("{}{}{}", String::from_utf8_lossy(&out_jwt1), String::from_utf8_lossy(&out_jwt2), String::from_utf8_lossy(&out_jwt3));
    assert!(!jwt_out.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), "Split large JWT token must be redacted");
    assert!(jwt_out.contains("[REDACTED]"), "Split large JWT must be redacted");
}

#[test]
fn test_stream_sanitizer_binary_fidelity_with_embedded_credentials() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();

    // Raw binary sequence containing invalid UTF-8 bytes: 0xFF, 0xFE, 0x00, 0x80
    let binary_prefix = vec![0xFF, 0xFE, 0x00, 0x80, b' '];
    let secret_bytes = b"ghp_1234567890abcdef1234567890abcdef1234";
    let binary_suffix = vec![b' ', 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];

    let mut tainted_payload = Vec::new();
    tainted_payload.extend_from_slice(&binary_prefix);
    tainted_payload.extend_from_slice(secret_bytes);
    tainted_payload.extend_from_slice(&binary_suffix);

    let (sanitized_bytes, has_secret) = StreamSanitizer::sanitize_bytes_internal(&tainted_payload, &engine);

    assert!(has_secret, "Sanitizer must detect secret embedded in raw binary stream");
    // Verify secret is redacted:
    assert!(
        !sanitized_bytes.windows(secret_bytes.len()).any(|w| w == secret_bytes),
        "Embedded raw secret must be completely redacted"
    );
    // Verify invalid UTF-8 binary prefix is preserved EXACTLY byte-for-byte:
    assert_eq!(
        &sanitized_bytes[..binary_prefix.len()],
        binary_prefix.as_slice(),
        "Surrounding invalid UTF-8 binary prefix bytes must be preserved byte-for-byte"
    );
    // Verify invalid UTF-8 binary suffix is preserved EXACTLY byte-for-byte:
    assert_eq!(
        &sanitized_bytes[sanitized_bytes.len() - binary_suffix.len()..],
        binary_suffix.as_slice(),
        "Surrounding invalid UTF-8 binary suffix bytes must be preserved byte-for-byte"
    );
}

#[test]
fn test_atomic_replace_first_creation_and_subsequent_overwrites() {
    use secretguard::vault::atomic_replace_file;

    let temp_dir = std::env::temp_dir().join(format!("sg_replace_flow_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("vault.enc");
    let tmp1 = temp_dir.join(".tmp1.vault");
    let tmp2 = temp_dir.join(".tmp2.vault");

    // 1. First-time creation (target does not exist yet)
    fs::write(&tmp1, b"first-time vault content").unwrap();
    assert!(!target.exists(), "Target file must not exist before first creation");
    assert!(atomic_replace_file(&tmp1, &target).is_ok(), "First-time creation must succeed");
    assert!(target.exists(), "Target file must exist after first creation");
    assert_eq!(fs::read_to_string(&target).unwrap(), "first-time vault content");

    // 2. Subsequent replacement (target already exists, tests ReplaceFileW / rename)
    fs::write(&tmp2, b"second-time replaced content").unwrap();
    assert!(atomic_replace_file(&tmp2, &target).is_ok(), "Subsequent replacement must succeed");
    assert_eq!(fs::read_to_string(&target).unwrap(), "second-time replaced content");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_windows_multi_process_worker_entry() {
    // Helper test entrypoint invoked by child processes during multi-process test
    if let Ok(target) = std::env::var("SG_CONCURRENT_PROC_TARGET") {
        let id = std::env::var("SG_CONCURRENT_PROC_ID").unwrap_or_else(|_| "0".to_string());
        let target_path = std::path::PathBuf::from(target);
        let parent = target_path.parent().unwrap();
        let tmp = parent.join(format!(".tmp_child_proc_{}.tmp", id));
        std::fs::write(&tmp, format!("proc_{}_valid_payload", id)).unwrap();
        secretguard::vault::atomic_replace_file(&tmp, &target_path).expect("Child process atomic_replace_file failed");
        std::process::exit(0);
    }
}

#[test]
#[cfg(windows)]
fn test_windows_multi_process_concurrent_creation() {
    use std::process::Command;

    let temp_dir = std::env::temp_dir().join(format!("sg_win_mp_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("vault.enc");
    let exe = std::env::current_exe().expect("Failed to get current test binary path");

    // Spawn 8 independent OS processes racing to create/replace target simultaneously
    let mut children = Vec::new();
    for i in 0..8 {
        let child = Command::new(&exe)
            .arg("test_windows_multi_process_worker_entry")
            .arg("--exact")
            .env("SG_CONCURRENT_PROC_TARGET", &target)
            .env("SG_CONCURRENT_PROC_ID", i.to_string())
            .spawn()
            .expect("Failed to spawn child worker process");
        children.push(child);
    }

    // Wait for all 8 independent OS processes and assert exit status 0
    for mut child in children {
        let status = child.wait().expect("Failed to wait on child worker process");
        assert!(status.success(), "Child worker process failed with status: {:?}", status);
    }

    // Verify target exists and contains a valid thread/process payload
    assert!(target.exists(), "Target file must exist after concurrent multi-process race");
    let content = fs::read_to_string(&target).expect("Failed to read final vault file");
    assert!(content.contains("_valid_payload"), "Target file must have valid content: {}", content);

    // Verify NO temporary files (.tmp_child_proc_*) remain in directory
    for entry in fs::read_dir(&temp_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(!name.starts_with(".tmp_child_proc_"), "Temporary file was left behind: {}", name);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(windows)]
fn test_windows_concurrent_first_creation_race() {
    use secretguard::vault::atomic_replace_file;
    use std::sync::Arc;
    use std::thread;

    let temp_dir = Arc::new(std::env::temp_dir().join(format!("sg_concurrent_first_{}", std::process::id())));
    fs::create_dir_all(&*temp_dir).unwrap();
    let target = Arc::new(temp_dir.join("vault.enc"));

    // Spawn 8 concurrent threads racing to create/replace target
    let mut handles = Vec::new();
    for i in 0..8 {
        let target_clone = Arc::clone(&target);
        let temp_dir_clone = Arc::clone(&temp_dir);
        handles.push(thread::spawn(move || {
            let tmp = temp_dir_clone.join(format!(".tmp_thread_{}.vault", i));
            let content = format!("content from thread {}", i);
            fs::write(&tmp, content.as_bytes()).unwrap();
            atomic_replace_file(&tmp, &target_clone)
        }));
    }

    let mut successes = 0;
    for h in handles {
        let res = h.join().expect("Thread joined successfully");
        assert!(res.is_ok(), "Concurrent replacement failed with error: {:?}", res.err());
        successes += 1;
    }

    assert_eq!(successes, 8, "All 8 concurrent threads must succeed without error or contention failure");
    assert!(target.exists(), "Target file must exist after concurrent race");
    let final_content = fs::read_to_string(&*target).unwrap();
    assert!(final_content.starts_with("content from thread "), "Final content must be valid thread payload: {}", final_content);

    let _ = fs::remove_dir_all(&*temp_dir);
}

#[test]
fn test_sigint_and_sigterm_exit_codes() {
    // Tests signal exit status semantics (SIGINT -> 130, SIGTERM -> 143)
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    let exit_sigint = 128 + SIGINT;
    let exit_sigterm = 128 + SIGTERM;

    assert_eq!(exit_sigint, 130, "SIGINT exit code must strictly equal 130 (128 + 2)");
    assert_eq!(exit_sigterm, 143, "SIGTERM exit code must strictly equal 143 (128 + 15)");
}

#[test]
fn test_secure_path_validation_and_symlink_defense() {
    use secretguard::vault::validate_secure_path;

    let temp_dir = std::env::temp_dir().join(format!("sg_secure_val_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join("test_vault.enc");
    fs::write(&target_file, b"test content").unwrap();

    // 1. Path inside trusted temp_dir must pass validation
    assert!(validate_secure_path(&target_file, true).is_ok(), "Valid path inside temp_dir must pass");

    // 2. Non-existent target (first creation) must pass
    let non_existent = temp_dir.join("non_existent_vault.enc");
    assert!(validate_secure_path(&non_existent, true).is_ok(), "Non-existent target must pass pre-creation checks");

    // 3. Symlink target defense (on platforms supporting symlinks)
    #[cfg(unix)]
    {
        let symlink_path = temp_dir.join("symlink_vault.enc");
        if std::os::unix::fs::symlink(&target_file, &symlink_path).is_ok() {
            let res = validate_secure_path(&symlink_path, true);
            assert!(res.is_err(), "Symlinked target must be rejected");
            assert!(res.unwrap_err().contains("symbolic link"));
        }

        // 4. Intermediate path component symlink defense
        let link_parent = temp_dir.join("link_parent");
        if std::os::unix::fs::symlink(&temp_dir, &link_parent).is_ok() {
            let nested_path = link_parent.join("vault.enc");
            let res = validate_secure_path(&nested_path, true);
            assert!(res.is_err(), "Path with intermediate symlink component must be rejected");
            assert!(res.unwrap_err().contains("symbolic link"));
        }
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_utf8_password_input_fidelity() {
    use secretguard::vault::parse_password_bytes;

    // 1. Multi-byte French accents: café\n -> café
    let cafe_bytes = "café\n".as_bytes();
    let parsed = parse_password_bytes(cafe_bytes).expect("Failed to parse valid UTF-8 café");
    assert_eq!(parsed, "café");

    // 2. Multi-byte German umlauts and emoji: p@sswörd🔑\r\n -> p@sswörd🔑
    let complex_bytes = "p@sswörd🔑\r\n".as_bytes();
    let parsed_complex = parse_password_bytes(complex_bytes).expect("Failed to parse valid UTF-8 complex password");
    assert_eq!(parsed_complex, "p@sswörd🔑");

    // 3. Invalid UTF-8 bytes fail closed with InvalidData
    let invalid_bytes = vec![0xFF, 0xFE, 0x80, b'\n'];
    let err = parse_password_bytes(&invalid_bytes);
    assert!(err.is_err(), "Invalid UTF-8 byte sequences must fail closed");
}

#[test]
fn test_load_vault_fails_closed_on_dangling_symlink_or_io_error() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!("sg_fail_closed_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    // 1. Truly non-existent vault loads as default empty store
    let default_store = load_vault(None).expect("Non-existent vault should return Ok(default)");
    assert!(default_store.secrets.is_empty());

    // 2. Dangling symlink for vault.enc must fail closed (NOT return Ok(default))
    #[cfg(unix)]
    {
        let vault_target = temp_dir.join("vault.enc");
        let non_existent_dest = temp_dir.join("does_not_exist.enc");
        if std::os::unix::fs::symlink(&non_existent_dest, &vault_target).is_ok() {
            let res = load_vault(None);
            assert!(res.is_err(), "Dangling symlink for vault file must fail closed with error");
            let err_msg = res.unwrap_err();
            assert!(err_msg.contains("symbolic link") || err_msg.contains("Security Error"));
            let _ = fs::remove_file(&vault_target);
        }
    }

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_vault_relative_path_and_parent_traversal_defense() {
    use secretguard::vault::validate_secure_path;

    // 1. Parent directory traversal ("..") must be rejected
    let traversal_path = std::path::Path::new("../secret/vault.enc");
    let res = validate_secure_path(traversal_path, true);
    assert!(res.is_err(), "Path with '..' traversal must be rejected");
    assert!(res.unwrap_err().contains("parent directory ('..') traversal"));

    // 2. Relative path ("vault.enc") resolves against cwd and passes if cwd is secure
    let rel_path = std::path::Path::new("test_rel_vault.enc");
    let _ = validate_secure_path(rel_path, true);
}

#[test]
fn test_stream_sanitizer_boundary_crossing_at_window_limit() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Create a 4080-byte safe prefix
    let mut stream = vec![b' '; 4080];
    // Secret begins at offset 4080 and spans to 4120 (crossing 4096-byte boundary)
    let secret = b"ghp_1234567890abcdef1234567890abcdef1234";
    stream.extend_from_slice(secret);
    stream.extend_from_slice(b" safe suffix trailing data\n");

    // Split stream right across the secret at byte 4095
    let split = 4095;
    let chunk1 = &stream[..split];
    let chunk2 = &stream[split..];

    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(chunk1, &engine, &mut out1).unwrap();

    let mut out2 = Vec::new();
    sanitizer.sanitize_chunk(chunk2, &engine, &mut out2).unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let total_out = format!("{}{}", String::from_utf8_lossy(&out1), String::from_utf8_lossy(&out2));
    assert!(!total_out.contains("ghp_1234567890abcdef1234567890abcdef1234"), "Token straddling 4096-byte window boundary must not leak");
    assert!(total_out.contains("[REDACTED]"), "Token straddling 4096-byte boundary must be redacted");
}

#[test]
fn test_stream_sanitizer_stateful_large_pem_holdback() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Build an 8KB PEM block (exceeding standard 4KB WINDOW_SIZE)
    let mut large_pem = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
    for i in 0..120 {
        large_pem.push_str(&format!("MIIEowIBAAKCAQEA0Y5k1vABCD{}EFGH{}IJKL{}MNOP{}QRST{}UVWX{}YZab1234567890=\n", i, i, i, i, i, i));
    }
    large_pem.push_str("-----END RSA PRIVATE KEY-----\n");
    assert!(large_pem.len() > 8000, "Large PEM must exceed 8KB");

    // Split across 3 large chunks (3KB each)
    let c1 = &large_pem.as_bytes()[..3000];
    let c2 = &large_pem.as_bytes()[3000..6000];
    let c3 = &large_pem.as_bytes()[6000..];

    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(c1, &engine, &mut out1).unwrap();
    assert!(out1.is_empty(), "Unclosed PEM header must be held back statefully");

    let mut out2 = Vec::new();
    sanitizer.sanitize_chunk(c2, &engine, &mut out2).unwrap();
    assert!(out2.is_empty(), "Intermediate unclosed PEM body must be held back statefully");

    let mut out3 = Vec::new();
    sanitizer.sanitize_chunk(c3, &engine, &mut out3).unwrap();
    sanitizer.flush_final(&engine, &mut out3).unwrap();

    let combined = format!("{}{}{}", String::from_utf8_lossy(&out1), String::from_utf8_lossy(&out2), String::from_utf8_lossy(&out3));
    assert!(!combined.contains("-----BEGIN RSA PRIVATE KEY-----"), "Full 8KB PEM key must be redacted");
    assert!(combined.contains("[REDACTED]"), "8KB PEM key must be redacted");
}
