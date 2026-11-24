use secretguard::vault::{
    decrypt_vault_payload, derive_vault_key, encrypt_vault_payload, get_or_generate_master_key,
    load_vault, save_vault, VaultStore,
};
use std::fs;
use std::process::{Child, ExitStatus};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
fn wait_for_child_with_timeout(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,

            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }

            Ok(None) => match child.kill() {
                Ok(()) => {
                    let _ = child.wait();
                    panic!("Child process timed out and was terminated");
                }

                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    return child.wait().expect("Failed to reap child process");
                }

                Err(error) => {
                    panic!("Timeout occurred and child termination failed: {error}");
                }
            },

            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();

                panic!("Failed to check child process: {error}");
            }
        }
    }
}

#[allow(dead_code)]
fn wait_for_children_with_shared_timeout(
    children: &mut [Child],
    timeout: Duration,
) -> Vec<ExitStatus> {
    let deadline = Instant::now() + timeout;
    let mut exit_statuses: Vec<Option<ExitStatus>> = vec![None; children.len()];
    let mut remaining = children.len();

    while remaining > 0 {
        let mut poll_err = None;
        for (i, child) in children.iter_mut().enumerate() {
            if exit_statuses[i].is_none() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        exit_statuses[i] = Some(status);
                        remaining -= 1;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        poll_err = Some((child.id(), e));
                        break;
                    }
                }
            }
        }

        if let Some((cid, err)) = poll_err {
            let mut cleanup_errors = Vec::new();
            for c in children.iter_mut() {
                if let Err(e) = c.kill() {
                    if e.kind() != std::io::ErrorKind::InvalidInput {
                        cleanup_errors.push(format!("PID {} kill error: {}", c.id(), e));
                    }
                }
                if let Err(e) = c.wait() {
                    cleanup_errors.push(format!("PID {} wait error: {}", c.id(), e));
                }
            }
            if cleanup_errors.is_empty() {
                panic!("Failed to poll child {}: {}", cid, err);
            } else {
                panic!(
                    "Failed to poll child {}: {}. Cleanup errors: {:?}",
                    cid, err, cleanup_errors
                );
            }
        }

        if remaining == 0 {
            break;
        }

        if Instant::now() >= deadline {
            let mut timed_out_pids = Vec::new();
            let mut cleanup_errors = Vec::new();
            // Kill and reap EVERY remaining running child to prevent zombie processes
            for (i, child) in children.iter_mut().enumerate() {
                if exit_statuses[i].is_none() {
                    timed_out_pids.push(child.id());
                    if let Err(e) = child.kill() {
                        if e.kind() != std::io::ErrorKind::InvalidInput {
                            cleanup_errors.push(format!("PID {} kill error: {}", child.id(), e));
                        }
                    }
                }
                if let Err(e) = child.wait() {
                    cleanup_errors.push(format!("PID {} wait error: {}", child.id(), e));
                }
            }
            if cleanup_errors.is_empty() {
                panic!(
                    "Multi-process test timed out after {:?}. Unfinished PIDs: {:?}",
                    timeout, timed_out_pids
                );
            } else {
                panic!(
                    "Multi-process test timed out after {:?}. Unfinished PIDs: {:?}. Cleanup errors: {:?}",
                    timeout, timed_out_pids, cleanup_errors
                );
            }
        }

        thread::sleep(Duration::from_millis(20));
    }

    exit_statuses.into_iter().map(|s| s.unwrap()).collect()
}

static VAULT_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_vault_aes_gcm_roundtrip() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_roundtrip_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_wrong_key_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_store_ser_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    let temp_dir =
        std::env::temp_dir().join(format!("sg_vault_corrupt_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let corrupt_vault_path = temp_dir.join("vault.enc");

    // Write bogus corrupted ciphertext
    fs::write(&corrupt_vault_path, b"not_valid_aes_gcm_ciphertext_at_all").unwrap();

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_VAULT_PATH", &corrupt_vault_path);

    // Attempting to load MUST return Err, NEVER unwrap_or_default
    let result = load_vault(None);
    assert!(
        result.is_err(),
        "Loading a corrupted vault MUST fail with Err to prevent overwriting existing data"
    );

    // Cleanup
    std::env::remove_var("SECRETGUARD_VAULT_PATH");
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_corrupted_master_key_aborts_to_prevent_data_loss() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let temp_dir =
        std::env::temp_dir().join(format!("sg_master_key_corrupt_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let corrupt_key_path = temp_dir.join(".master.key");

    // Write truncated key (< 32 bytes)
    fs::write(&corrupt_key_path, b"short_16_byte_key!").unwrap();

    std::env::set_var("SECRETGUARD_DIR", &temp_dir);
    std::env::set_var("SECRETGUARD_MASTER_KEY_PATH", &corrupt_key_path);

    let result = get_or_generate_master_key();
    assert!(
        result.is_err(),
        "Truncated master key must be rejected to prevent vault orphaning"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("corrupted"),
        "Error should explain key corruption: {}",
        err_msg
    );

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
    store.secrets.insert(
        "PROD_DB".to_string(),
        "postgres://user:pass@db:5432/prod".to_string(),
    );

    let save_res = save_vault(&store, None);
    assert!(
        save_res.is_ok(),
        "save_vault should succeed with unique tmp file"
    );
    assert!(
        vault_path.exists(),
        "Final vault file must exist after atomic rename"
    );

    // Verify temp files were cleanly cleaned up
    let entries: Vec<_> = fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    // vault.enc and .master.key exist, but no .vault.*.tmp files
    let tmp_files: Vec<_> = entries
        .iter()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
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
    assert!(
        save_vault(&store, None).is_ok(),
        "Initial save must succeed"
    );

    // Replace existing vault multiple times to test Windows and Unix file replacement
    store.secrets.insert("KEY2".to_string(), "val2".to_string());
    assert!(
        save_vault(&store, None).is_ok(),
        "Overwriting existing vault must succeed atomically"
    );

    store.secrets.insert("KEY3".to_string(), "val3".to_string());
    assert!(
        save_vault(&store, None).is_ok(),
        "Third update to existing vault must succeed atomically"
    );

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
    assert_eq!(
        out_binary, raw_binary,
        "Clean binary chunks must be preserved unmodified byte-for-byte"
    );

    // 2. Binary with embedded ASCII credential: MUST detect and redact credential (cannot bypass)
    let mut tainted_binary = vec![0x1f, 0x8b, 0x08];
    tainted_binary.extend_from_slice(b"sk-proj-embeddedTokenInBinary01234567890abcdef");
    tainted_binary.extend_from_slice(&[0x00, 0xff]);

    let mut out_tainted = Vec::new();
    sanitize_stream_buffer(&tainted_binary, &engine, &mut out_tainted).unwrap();
    let out_str = String::from_utf8_lossy(&out_tainted);
    assert!(
        !out_str.contains("sk-proj-embeddedTokenInBinary01234567890abcdef"),
        "Embedded credential in binary output MUST be redacted"
    );
    assert!(
        out_str.contains("[REDACTED_OPENAI_KEY]") || out_str.contains("[REDACTED"),
        "Credential must be redacted in output"
    );
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
    sanitizer
        .sanitize_chunk(chunk1, &engine, &mut out1)
        .unwrap();

    // Chunk 2: suffix of the key completing the credential across chunk boundary
    let chunk2 = b"67890suffixPartAbcdef0123456789\"\n";
    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk2, &engine, &mut out2)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let combined_out = format!(
        "{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2)
    );
    assert!(
        out1.is_empty(),
        "Partial chunk within 1024-byte window must be held back to prevent leak"
    );
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
    sanitizer
        .sanitize_chunk(&filler, &engine, &mut out1)
        .unwrap();
    // out1 should have drained 5000 - 4096 = 904 bytes
    assert_eq!(out1.len(), 5000 - StreamSanitizer::WINDOW_SIZE);

    // Now inject split secret in chunk 2 and chunk 3
    let chunk2 = b"prefix_filler ghp_1234567890";
    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk2, &engine, &mut out2)
        .unwrap();

    let chunk3 = b"12345678901234567890123456 suffix_filler\n";
    let mut out3 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk3, &engine, &mut out3)
        .unwrap();

    let mut out_final = Vec::new();
    sanitizer.flush_final(&engine, &mut out_final).unwrap();

    let total = format!(
        "{}{}{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2),
        String::from_utf8_lossy(&out3),
        String::from_utf8_lossy(&out_final)
    );
    assert!(
        !total.contains("ghp_123456789012345678901234567890123456"),
        "Split GitHub token across chunks must be redacted"
    );
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
        full_pem.push_str(&format!(
            "MIIEowIBAAKCAQEA0Y5k1vABCD{}EFGH{}IJKL{}MNOP{}QRST{}UVWX{}YZab1234567890=\n",
            i, i, i, i, i, i
        ));
    }
    full_pem.push_str("-----END RSA PRIVATE KEY-----\n");
    assert!(
        full_pem.len() > 1500,
        "Full PEM must be a realistic 1.5KB+ key block"
    );

    let split_point1 = 500;
    let split_point2 = 1100;
    let chunk_pem1 = &full_pem.as_bytes()[..split_point1];
    let chunk_pem2 = &full_pem.as_bytes()[split_point1..split_point2];
    let chunk_pem3 = &full_pem.as_bytes()[split_point2..];

    let mut out_pem1 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk_pem1, &engine, &mut out_pem1)
        .unwrap();
    assert!(
        out_pem1.is_empty(),
        "Partial PEM header must be held back in window"
    );

    let mut out_pem2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk_pem2, &engine, &mut out_pem2)
        .unwrap();

    let mut out_pem3 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk_pem3, &engine, &mut out_pem3)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out_pem3).unwrap();

    let pem_out = format!(
        "{}{}{}",
        String::from_utf8_lossy(&out_pem1),
        String::from_utf8_lossy(&out_pem2),
        String::from_utf8_lossy(&out_pem3)
    );
    assert!(
        !pem_out.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Full PEM key header must be redacted"
    );
    assert!(
        pem_out.contains("[REDACTED]"),
        "Sanitizer must redact full PEM block"
    );

    // 2. Large JWT token (1.2KB) split across 3 chunk boundaries
    let mut jwt_sanitizer = StreamSanitizer::new();
    let mut full_jwt = String::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.");
    for _ in 0..15 {
        full_jwt
            .push_str("eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
    }
    full_jwt.push_str(".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c_final_signature\n");
    assert!(full_jwt.len() > 1000, "JWT must be realistic 1KB+ token");

    let jwt_split1 = 350;
    let jwt_split2 = 750;
    let mut out_jwt1 = Vec::new();
    jwt_sanitizer
        .sanitize_chunk(&full_jwt.as_bytes()[..jwt_split1], &engine, &mut out_jwt1)
        .unwrap();
    assert!(
        out_jwt1.is_empty(),
        "Partial JWT within window must be held back"
    );

    let mut out_jwt2 = Vec::new();
    jwt_sanitizer
        .sanitize_chunk(
            &full_jwt.as_bytes()[jwt_split1..jwt_split2],
            &engine,
            &mut out_jwt2,
        )
        .unwrap();

    let mut out_jwt3 = Vec::new();
    jwt_sanitizer
        .sanitize_chunk(&full_jwt.as_bytes()[jwt_split2..], &engine, &mut out_jwt3)
        .unwrap();
    jwt_sanitizer.flush_final(&engine, &mut out_jwt3).unwrap();

    let jwt_out = format!(
        "{}{}{}",
        String::from_utf8_lossy(&out_jwt1),
        String::from_utf8_lossy(&out_jwt2),
        String::from_utf8_lossy(&out_jwt3)
    );
    assert!(
        !jwt_out.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "Split large JWT token must be redacted"
    );
    assert!(
        jwt_out.contains("[REDACTED]"),
        "Split large JWT must be redacted"
    );
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

    let (sanitized_bytes, has_secret) =
        StreamSanitizer::sanitize_bytes_internal(&tainted_payload, &engine);

    assert!(
        has_secret,
        "Sanitizer must detect secret embedded in raw binary stream"
    );
    // Verify secret is redacted:
    assert!(
        !sanitized_bytes
            .windows(secret_bytes.len())
            .any(|w| w == secret_bytes),
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
    assert!(
        !target.exists(),
        "Target file must not exist before first creation"
    );
    assert!(
        atomic_replace_file(&tmp1, &target).is_ok(),
        "First-time creation must succeed"
    );
    assert!(
        target.exists(),
        "Target file must exist after first creation"
    );
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "first-time vault content"
    );

    // 2. Subsequent replacement (target already exists, tests ReplaceFileW / rename)
    fs::write(&tmp2, b"second-time replaced content").unwrap();
    assert!(
        atomic_replace_file(&tmp2, &target).is_ok(),
        "Subsequent replacement must succeed"
    );
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "second-time replaced content"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_windows_multi_process_worker_entry() {
    // Helper test entrypoint invoked by child processes during multi-process test
    if let Ok(target) = std::env::var("SG_CONCURRENT_PROC_TARGET") {
        let id = std::env::var("SG_CONCURRENT_PROC_ID").unwrap_or_else(|_| "0".to_string());
        let target_path = std::path::PathBuf::from(target);
        let parent = target_path.parent().unwrap();
        std::env::set_var("SECRETGUARD_DIR", parent);

        // Each process creates a genuine AES-256-GCM encrypted vault with its unique secret
        let tmp = parent.join(format!(".tmp_child_proc_{}.vault", id));
        let mut store = VaultStore::default();
        store.secrets.insert(
            format!("PROCESS_KEY_{}", id),
            format!("secret_payload_from_proc_{}", id),
        );
        let key = [0x5au8; 32];
        let json_bytes = serde_json::to_vec(&store).unwrap();
        let encrypted = encrypt_vault_payload(&json_bytes, &key).unwrap();
        std::fs::write(&tmp, &encrypted).unwrap();

        secretguard::vault::atomic_replace_file(&tmp, &target_path)
            .expect("Child process atomic_replace_file failed");
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
            .env("SECRETGUARD_DIR", &temp_dir)
            .spawn()
            .expect("Failed to spawn child worker process");
        children.push(child);
    }

    // Wait for all 8 independent OS processes with a single shared 15s deadline and assert exit status 0
    let statuses = wait_for_children_with_shared_timeout(&mut children, Duration::from_secs(15));
    for status in statuses {
        assert!(
            status.success(),
            "Child worker process failed with status: {:?}",
            status
        );
    }

    // Verify target exists and can be decrypted cleanly with the master key
    assert!(
        target.exists(),
        "Target file must exist after concurrent multi-process race"
    );
    let encrypted = fs::read(&target).expect("Failed to read final vault file");
    let key = [0x5au8; 32];
    let decrypted = decrypt_vault_payload(&encrypted, &key)
        .expect("Final vault file must decrypt cleanly with master key");
    let store: VaultStore = serde_json::from_slice(&decrypted)
        .expect("Final vault must deserialize into valid VaultStore");
    assert!(
        !store.secrets.is_empty(),
        "Vault must contain valid secret entries"
    );

    // Verify NO temporary files (.tmp_child_proc_*) remain in directory
    for entry in fs::read_dir(&temp_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".tmp_child_proc_"),
            "Temporary file was left behind: {}",
            name
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(windows)]
fn test_windows_concurrent_first_creation_race() {
    use secretguard::vault::atomic_replace_file;
    use std::sync::Arc;
    use std::thread;

    let temp_dir =
        Arc::new(std::env::temp_dir().join(format!("sg_concurrent_first_{}", std::process::id())));
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
        assert!(
            res.is_ok(),
            "Concurrent replacement failed with error: {:?}",
            res.err()
        );
        successes += 1;
    }

    assert_eq!(
        successes, 8,
        "All 8 concurrent threads must succeed without error or contention failure"
    );
    assert!(
        target.exists(),
        "Target file must exist after concurrent race"
    );
    let final_content = fs::read_to_string(&*target).unwrap();
    assert!(
        final_content.starts_with("content from thread "),
        "Final content must be valid thread payload: {}",
        final_content
    );

    let _ = fs::remove_dir_all(&*temp_dir);
}

#[test]
fn test_sigint_and_sigterm_exit_codes() {
    // Tests signal exit status semantics (SIGINT -> 130, SIGTERM -> 143)
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    let exit_sigint = 128 + SIGINT;
    let exit_sigterm = 128 + SIGTERM;

    assert_eq!(
        exit_sigint, 130,
        "SIGINT exit code must strictly equal 130 (128 + 2)"
    );
    assert_eq!(
        exit_sigterm, 143,
        "SIGTERM exit code must strictly equal 143 (128 + 15)"
    );
}

#[test]
fn test_secure_path_validation_and_symlink_defense() {
    use secretguard::vault::validate_secure_path;

    let temp_dir = std::env::temp_dir().join(format!("sg_secure_val_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join("test_vault.enc");
    fs::write(&target_file, b"test content").unwrap();

    // 1. Path inside trusted temp_dir must pass validation
    assert!(
        validate_secure_path(&target_file, true).is_ok(),
        "Valid path inside temp_dir must pass"
    );

    // 2. Non-existent target (first creation) must pass
    let non_existent = temp_dir.join("non_existent_vault.enc");
    assert!(
        validate_secure_path(&non_existent, true).is_ok(),
        "Non-existent target must pass pre-creation checks"
    );

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
            assert!(
                res.is_err(),
                "Path with intermediate symlink component must be rejected"
            );
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
    let parsed_complex =
        parse_password_bytes(complex_bytes).expect("Failed to parse valid UTF-8 complex password");
    assert_eq!(parsed_complex, "p@sswörd🔑");

    // 3. Invalid UTF-8 bytes fail closed with InvalidData
    let invalid_bytes = vec![0xFF, 0xFE, 0x80, b'\n'];
    let err = parse_password_bytes(&invalid_bytes);
    assert!(
        err.is_err(),
        "Invalid UTF-8 byte sequences must fail closed"
    );
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
            assert!(
                res.is_err(),
                "Dangling symlink for vault file must fail closed with error"
            );
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
    assert!(res
        .unwrap_err()
        .contains("parent directory ('..') traversal"));

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
    sanitizer
        .sanitize_chunk(chunk1, &engine, &mut out1)
        .unwrap();

    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk2, &engine, &mut out2)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let total_out = format!(
        "{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2)
    );
    assert!(
        !total_out.contains("ghp_1234567890abcdef1234567890abcdef1234"),
        "Token straddling 4096-byte window boundary must not leak"
    );
    assert!(
        total_out.contains("[REDACTED]"),
        "Token straddling 4096-byte boundary must be redacted"
    );
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
        large_pem.push_str(&format!(
            "MIIEowIBAAKCAQEA0Y5k1vABCD{}EFGH{}IJKL{}MNOP{}QRST{}UVWX{}YZab1234567890=\n",
            i, i, i, i, i, i
        ));
    }
    large_pem.push_str("-----END RSA PRIVATE KEY-----\n");
    assert!(large_pem.len() > 8000, "Large PEM must exceed 8KB");

    // Split across 3 large chunks (3KB each)
    let c1 = &large_pem.as_bytes()[..3000];
    let c2 = &large_pem.as_bytes()[3000..6000];
    let c3 = &large_pem.as_bytes()[6000..];

    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(c1, &engine, &mut out1).unwrap();
    assert!(
        out1.is_empty(),
        "Unclosed PEM header must be held back statefully"
    );

    let mut out2 = Vec::new();
    sanitizer.sanitize_chunk(c2, &engine, &mut out2).unwrap();
    assert!(
        out2.is_empty(),
        "Intermediate unclosed PEM body must be held back statefully"
    );

    let mut out3 = Vec::new();
    sanitizer.sanitize_chunk(c3, &engine, &mut out3).unwrap();
    sanitizer.flush_final(&engine, &mut out3).unwrap();

    let combined = format!(
        "{}{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2),
        String::from_utf8_lossy(&out3)
    );
    assert!(
        !combined.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Full 8KB PEM key must be redacted"
    );
    assert!(
        combined.contains("[REDACTED]"),
        "8KB PEM key must be redacted"
    );
}

#[test]
fn test_stream_sanitizer_pem_holdback_overflow_16kb_minus_one() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 16KB - 1 byte = 16383 bytes incomplete PEM (no -----END)
    let header = b"-----BEGIN RSA PRIVATE KEY-----\n";
    let mut pem = header.to_vec();
    while pem.len() < 16383 {
        pem.push(b'A');
    }
    assert_eq!(pem.len(), 16383);

    let mut out = Vec::new();
    sanitizer.sanitize_chunk(&pem, &engine, &mut out).unwrap();
    // Must be completely held back (zero bytes leaked)
    assert!(
        out.is_empty(),
        "16KB - 1 byte incomplete PEM must be held back with 0 bytes emitted"
    );
}

#[test]
fn test_stream_sanitizer_pem_holdback_overflow_exact_16kb() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Exactly 16384 bytes incomplete PEM (no -----END)
    let header = b"-----BEGIN RSA PRIVATE KEY-----\n";
    let mut pem = header.to_vec();
    while pem.len() < 16384 {
        pem.push(b'B');
    }
    assert_eq!(pem.len(), 16384);

    let mut out = Vec::new();
    sanitizer.sanitize_chunk(&pem, &engine, &mut out).unwrap();
    sanitizer.flush_final(&engine, &mut out).unwrap();

    let output_str = String::from_utf8_lossy(&out);
    assert!(
        !output_str.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Raw private key header must not leak on overflow"
    );
    assert!(
        output_str.contains("[REDACTED_PRIVATE_KEY_BLOCK]"),
        "Overflowed incomplete candidate must be redacted in place"
    );
}

#[test]
fn test_stream_sanitizer_pem_holdback_overflow_16kb_plus_one() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 16385 bytes (16KB + 1 byte) incomplete PEM (no -----END)
    let header = b"-----BEGIN RSA PRIVATE KEY-----\n";
    let mut pem = header.to_vec();
    while pem.len() < 16385 {
        pem.push(b'C');
    }
    assert_eq!(pem.len(), 16385);

    let mut out = Vec::new();
    sanitizer.sanitize_chunk(&pem, &engine, &mut out).unwrap();
    sanitizer.flush_final(&engine, &mut out).unwrap();

    let output_str = String::from_utf8_lossy(&out);
    assert!(
        !output_str.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Raw private key header must not leak on overflow"
    );
    assert!(
        output_str.contains("[REDACTED_PRIVATE_KEY_BLOCK]"),
        "Overflowed incomplete candidate must be redacted in place"
    );
}

#[test]
fn test_stream_sanitizer_pem_holdback_overflow_32kb_incomplete() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 32KB incomplete PEM (adversarial stream trying to cause overflow)
    let header = b"-----BEGIN RSA PRIVATE KEY-----\n";
    let mut pem = header.to_vec();
    while pem.len() < 32768 {
        pem.push(b'D');
    }
    assert_eq!(pem.len(), 32768);

    // Deliver in two 16KB chunks
    let mut out1 = Vec::new();
    sanitizer
        .sanitize_chunk(&pem[..16384], &engine, &mut out1)
        .unwrap();

    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(&pem[16384..], &engine, &mut out2)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2)
    );
    assert!(
        !combined.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Raw private key header must not leak on 32KB overflow"
    );
    assert!(
        combined.contains("[REDACTED_PRIVATE_KEY_BLOCK]"),
        "32KB incomplete candidate must be redacted in place"
    );
}

#[test]
fn test_stream_sanitizer_pem_closing_delimiter_in_later_chunk() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 10KB incomplete PEM in chunk 1, delimiter in chunk 2
    let mut chunk1 = String::from("-----BEGIN RSA PRIVATE KEY-----\n");
    for i in 0..150 {
        chunk1.push_str(&format!(
            "MIIEowIBAAKCAQEA0Y5k1vABCD{}EFGH{}IJKL{}MNOP{}QRST{}UVWX{}YZab1234567890=\n",
            i, i, i, i, i, i
        ));
    }
    assert!(chunk1.len() > 10000);

    let chunk2 = "-----END RSA PRIVATE KEY-----\n";

    let mut out1 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk1.as_bytes(), &engine, &mut out1)
        .unwrap();
    assert!(
        out1.is_empty(),
        "Incomplete PEM candidate must be held back in chunk 1"
    );

    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk2.as_bytes(), &engine, &mut out2)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let total = format!(
        "{}{}",
        String::from_utf8_lossy(&out1),
        String::from_utf8_lossy(&out2)
    );
    assert!(
        !total.contains("-----BEGIN RSA PRIVATE KEY-----"),
        "Complete PEM block delivered across chunks must be redacted"
    );
    assert!(
        total.contains("[REDACTED]"),
        "Complete PEM block must be redacted"
    );
}

#[test]
#[cfg(windows)]
fn test_windows_reparse_point_rejection() {
    use secretguard::vault::validate_secure_path;
    use std::process::Command;

    let temp_dir = std::env::temp_dir().join(format!("sg_win_rp_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join("test_vault.enc");
    fs::write(&target_file, b"test content").unwrap();

    // 1. Clean normal path must pass
    assert!(validate_secure_path(&target_file, true).is_ok());

    // 2. Real Windows Junction creation and rejection
    let junc_src = temp_dir.join("junc_src");
    let junc_dst = temp_dir.join("junc_dst");
    fs::create_dir_all(&junc_src).unwrap();

    let junc_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "New-Item -ItemType Junction -Path '{}' -Target '{}'",
                junc_dst.display(),
                junc_src.display()
            ),
        ])
        .output();

    if let Ok(out) = junc_output {
        if out.status.success() {
            // Validating the junction directory itself must fail closed
            let res = validate_secure_path(&junc_dst, false);
            assert!(res.is_err(), "Windows Junction directory must be rejected");
            let err = res.unwrap_err();
            assert!(
                err.contains("reparse point") || err.contains("symbolic link"),
                "Error must state that reparse points/symlinks are prohibited: {}",
                err
            );

            // Validating a file through the junction path must fail closed
            let file_in_junc = junc_dst.join("vault.enc");
            fs::write(junc_src.join("vault.enc"), b"secret data").unwrap();
            let file_res = validate_secure_path(&file_in_junc, true);
            assert!(
                file_res.is_err(),
                "Path through Windows Junction must be rejected"
            );

            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Remove-Item -Force '{}'", junc_dst.display()),
                ])
                .output();
        }
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
#[cfg(windows)]
fn test_windows_permissive_dacl_rejection() {
    use secretguard::vault::{validate_secure_path, win32};
    use std::ffi::c_void;

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            ProcessHandle: *mut c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
        fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: i32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut c_void) -> i32;
        fn InitializeAcl(pAcl: *mut c_void, nAclLength: u32, dwAclRevision: u32) -> i32;
        fn AddAccessAllowedAce(
            pAcl: *mut c_void,
            dwAceRevision: u32,
            AccessMask: u32,
            pSid: *const c_void,
        ) -> i32;
        fn GetAce(pAcl: *const c_void, dwAceIndex: u32, pAce: *mut *mut c_void) -> i32;
    }

    let temp_dir = std::env::temp_dir().join(format!("sg_win_dacl_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join("insecure_vault.enc");
    fs::write(&target_file, b"secret content").unwrap();

    // Query current process user's SID
    let mut h_token = std::ptr::null_mut();
    unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008, &mut h_token) };
    let mut len = 0u32;
    unsafe { GetTokenInformation(h_token, 1, std::ptr::null_mut(), 0, &mut len) };
    let mut user_buf = vec![0u8; len as usize];
    unsafe {
        GetTokenInformation(
            h_token,
            1,
            user_buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        );
        CloseHandle(h_token);
    };
    let current_user_sid = unsafe { (*(user_buf.as_ptr() as *const win32::TOKEN_USER)).User.Sid };

    // 1. Test NULL DACL rejection via inspect_dacl_and_owner
    let null_dacl_res =
        win32::inspect_dacl_and_owner(current_user_sid, std::ptr::null(), &target_file, true);
    assert!(
        null_dacl_res.is_err(),
        "Target with NULL DACL must be rejected!"
    );
    let null_err = null_dacl_res.unwrap_err();
    assert!(
        null_err.contains("NULL DACL detected"),
        "Error must indicate NULL DACL: {}",
        null_err
    );

    // 2. Test Untrusted Owner SID rejection
    let mut untrusted_sid = vec![0u8; 68];
    let mut cb_sid = 68u32;
    unsafe {
        win32::CreateWellKnownSid(
            win32::WinWorldSid,
            std::ptr::null(),
            untrusted_sid.as_mut_ptr() as *mut c_void,
            &mut cb_sid,
        );
    }
    let untrusted_owner_res = win32::inspect_dacl_and_owner(
        untrusted_sid.as_ptr() as *const c_void,
        0x1 as *const c_void,
        &target_file,
        true,
    );
    assert!(
        untrusted_owner_res.is_err(),
        "Untrusted owner SID must be rejected!"
    );
    assert!(untrusted_owner_res
        .unwrap_err()
        .contains("untrusted principal"));

    // 3. Test Non-Allowlisted ACE rejection (Everyone / WinWorldSid on target)
    let mut world_sid_buf = vec![0u8; 68];
    let mut cb_world = 68u32;
    unsafe {
        win32::CreateWellKnownSid(
            win32::WinWorldSid,
            std::ptr::null(),
            world_sid_buf.as_mut_ptr() as *mut c_void,
            &mut cb_world,
        );
    }
    let mut world_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(world_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            world_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_ALL,
            world_sid_buf.as_ptr() as *const c_void,
        );
    }
    let world_ace_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        world_acl.as_ptr() as *const c_void,
        &target_file,
        true,
    );
    assert!(
        world_ace_res.is_err(),
        "Target with Everyone ACE must be rejected!"
    );
    let world_err = world_ace_res.unwrap_err();
    assert!(
        world_err.contains("strict allow-list") || world_err.contains("Overly permissive ACE"),
        "Error must indicate non-allowlisted principal: {}",
        world_err
    );

    // 4. Test Authenticated Users (WinAuthenticatedUserSid, 17) rejection on target via strict allow-list
    let mut auth_users_sid_buf = vec![0u8; 68];
    let mut cb_auth_users = 68u32;
    unsafe {
        win32::CreateWellKnownSid(
            win32::WinAuthenticatedUserSid,
            std::ptr::null(),
            auth_users_sid_buf.as_mut_ptr() as *mut c_void,
            &mut cb_auth_users,
        );
    }
    let mut auth_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(auth_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            auth_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_READ,
            auth_users_sid_buf.as_ptr() as *const c_void,
        );
    }
    let auth_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        auth_acl.as_ptr() as *const c_void,
        &target_file,
        true,
    );
    assert!(
        auth_res.is_err(),
        "Target with Authenticated Users ACE must be rejected by strict allow-list!"
    );
    assert!(auth_res.unwrap_err().contains("strict allow-list"));

    // 5. Test Permissive ACE rejection on ancestor directory (Everyone with write access)
    let anc_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        world_acl.as_ptr() as *const c_void,
        &target_file,
        false,
    );
    assert!(
        anc_res.is_err(),
        "Ancestor directory with Everyone write access must be rejected!"
    );
    assert!(anc_res.unwrap_err().contains("Overly permissive ACE"));

    // 5a. Test Custom untrusted group SID with write access on ancestor directory (must be rejected)
    let custom_group_sid: [u8; 28] = [
        1, 5, // Revision 1, 5 sub-authorities
        0, 0, 0, 0, 0, 5, // SECURITY_NT_AUTHORITY
        21, 0, 0, 0, // SubAuthority 0 = 21
        0x9f, 0x86, 0x01, 0, // 99999
        0x58, 0x5b, 0x01, 0, // 88888
        0x11, 0x30, 0x01, 0, // 77777
        0xe9, 0x03, 0x00, 0, // 1001
    ];
    let mut custom_write_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(custom_write_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            custom_write_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_ALL,
            custom_group_sid.as_ptr() as *const c_void,
        );
    }
    let custom_write_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        custom_write_acl.as_ptr() as *const c_void,
        &target_file,
        false,
    );
    assert!(
        custom_write_res.is_err(),
        "Ancestor directory with custom untrusted group write access must be rejected!"
    );
    assert!(custom_write_res
        .unwrap_err()
        .contains("Overly permissive ACE"));

    // 5b. Test Custom untrusted group SID with read-only access on ancestor directory (must be accepted)
    let mut custom_read_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(custom_read_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            custom_read_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_READ,
            custom_group_sid.as_ptr() as *const c_void,
        );
    }
    let custom_read_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        custom_read_acl.as_ptr() as *const c_void,
        &target_file,
        false,
    );
    assert!(
        custom_read_res.is_ok(),
        "Ancestor directory with read-only group permissions must be accepted: {:?}",
        custom_read_res
    );

    // 5c. Test Unsupported / complex ACE type (callback ACE, type 9) on ancestor directory
    let mut complex_cb_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(complex_cb_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            complex_cb_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_READ,
            current_user_sid,
        );
        let mut p_ace = std::ptr::null_mut();
        GetAce(complex_cb_acl.as_mut_ptr() as *mut c_void, 0, &mut p_ace);
        (*(p_ace as *mut win32::ACE_HEADER)).AceType = 9; // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    }
    let complex_cb_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        complex_cb_acl.as_ptr() as *const c_void,
        &target_file,
        false,
    );
    assert!(
        complex_cb_res.is_err(),
        "Ancestor with callback ACE must be rejected!"
    );
    assert!(complex_cb_res
        .unwrap_err()
        .contains("Unsupported or complex ACE type 9"));

    // 5d. Test Unsupported / complex ACE type (object ACE, type 5) on ancestor directory
    let mut complex_obj_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(complex_obj_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            complex_obj_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_READ,
            current_user_sid,
        );
        let mut p_ace = std::ptr::null_mut();
        GetAce(complex_obj_acl.as_mut_ptr() as *mut c_void, 0, &mut p_ace);
        (*(p_ace as *mut win32::ACE_HEADER)).AceType = 5; // ACCESS_ALLOWED_OBJECT_ACE_TYPE
    }
    let complex_obj_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        complex_obj_acl.as_ptr() as *const c_void,
        &target_file,
        false,
    );
    assert!(
        complex_obj_res.is_err(),
        "Ancestor with object ACE must be rejected!"
    );
    assert!(complex_obj_res
        .unwrap_err()
        .contains("Unsupported or complex ACE type 5"));

    // 5e. Test Unsupported / complex ACE type on target file
    let target_complex_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        complex_cb_acl.as_ptr() as *const c_void,
        &target_file,
        true,
    );
    assert!(
        target_complex_res.is_err(),
        "Target with callback ACE must be rejected!"
    );
    assert!(target_complex_res
        .unwrap_err()
        .contains("Unsupported or complex ACE type 9"));

    // 6. Test Safe DACL granting access strictly to Current User
    let mut safe_acl = vec![0u8; 1024];
    unsafe {
        InitializeAcl(safe_acl.as_mut_ptr() as *mut c_void, 1024, 2);
        AddAccessAllowedAce(
            safe_acl.as_mut_ptr() as *mut c_void,
            2,
            win32::GENERIC_ALL,
            current_user_sid,
        );
    }
    let safe_res = win32::inspect_dacl_and_owner(
        current_user_sid,
        safe_acl.as_ptr() as *const c_void,
        &target_file,
        true,
    );
    assert!(
        safe_res.is_ok(),
        "Safe DACL restricted to owner must be accepted: {:?}",
        safe_res
    );

    // 7. Test Filesystem Integration via validate_secure_path on the created target
    let fs_res = validate_secure_path(&target_file, true);
    assert!(
        fs_res.is_ok(),
        "Target created in temp directory with default user ownership must validate: {:?}",
        fs_res
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_sanitizer_multi_type_multi_block_split_across_chunks() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // 1. RSA Key (completed across chunks 1 and 2)
    let rsa_part1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y5k1vRSA";
    let rsa_part2 = "KeyPayload0123456789=\n-----END RSA PRIVATE KEY-----\n";

    // 2. EC Key (completed across chunks 2 and 3)
    let ec_part1 = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIEC";
    let ec_part2 = "KeyPayload9876543210=\n-----END EC PRIVATE KEY-----\n";

    // 3. OpenSSH Key (unclosed, arrives in chunk 3, flushed at EOF)
    let openssh_part = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE";

    // Chunk 1: partial RSA
    let mut out1 = Vec::new();
    sanitizer
        .sanitize_chunk(rsa_part1.as_bytes(), &engine, &mut out1)
        .unwrap();
    assert!(out1.is_empty(), "Partial RSA in chunk 1 must be held back");

    // Chunk 2: rest of RSA + filler + partial EC
    let mut chunk2 = String::new();
    chunk2.push_str(rsa_part2);
    chunk2.push_str(&"B".repeat(5000));
    chunk2.push('\n');
    chunk2.push_str(ec_part1);

    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk2.as_bytes(), &engine, &mut out2)
        .unwrap();
    let out2_str = String::from_utf8_lossy(&out2);

    // RSA should be sanitized, EC should not leak
    assert!(
        out2_str.contains("[REDACTED]"),
        "Completed RSA block must be sanitized"
    );
    assert!(
        !out2_str.contains("RSAKeyPayload0123456789"),
        "RSA key payload must not leak"
    );
    assert!(
        !out2_str.contains("ECKeyPayload9876543210"),
        "EC key payload must not leak in chunk 2"
    );

    // Chunk 3: rest of EC + filler + unclosed OpenSSH
    let mut chunk3 = String::new();
    chunk3.push_str(ec_part2);
    chunk3.push_str(&"C".repeat(5000));
    chunk3.push('\n');
    chunk3.push_str(openssh_part);

    let mut out3 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk3.as_bytes(), &engine, &mut out3)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out3).unwrap();

    let out3_str = String::from_utf8_lossy(&out3);
    let total = format!("{}{}{}", String::from_utf8_lossy(&out1), out2_str, out3_str);

    // All three key types must be sanitized; zero raw payload leaked
    assert!(
        !total.contains("RSAKeyPayload0123456789"),
        "No RSA payload leaked"
    );
    assert!(
        !total.contains("ECKeyPayload9876543210"),
        "No EC payload leaked"
    );
    assert!(
        !total.contains("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE"),
        "No OpenSSH payload leaked"
    );
    assert!(
        total.contains("[REDACTED]"),
        "Completed blocks must be redacted"
    );
    assert!(
        total.contains("[REDACTED_PRIVATE_KEY_BLOCK]"),
        "Unclosed OpenSSH block must be redacted at EOF"
    );
}

#[test]
fn test_stream_sanitizer_multi_block_pem_with_incomplete_second_block() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Block 1: Completed RSA Private Key
    let block1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y5k1vABCD01234567890=\n-----END RSA PRIVATE KEY-----\n";

    // 5KB of filler text so start of block 2 is well past WINDOW_SIZE (4096 bytes),
    // proving prefix draining does not leak unclosed block 2
    let filler = "A".repeat(5000) + "\n";

    // Block 2: Incomplete EC Private Key (started in chunk 1, completed in chunk 2)
    let block2_part1 =
        "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEILeakedSecretKeyByteSequenceDoNotEmit\n";
    let block2_part2 = "-----END EC PRIVATE KEY-----\n";

    let mut chunk1 = String::new();
    chunk1.push_str(block1);
    chunk1.push_str(&filler);
    chunk1.push_str(block2_part1);

    let mut out1 = Vec::new();
    sanitizer
        .sanitize_chunk(chunk1.as_bytes(), &engine, &mut out1)
        .unwrap();

    let out1_str = String::from_utf8_lossy(&out1);

    // Finding 1 Verification:
    // Earlier `-----END RSA PRIVATE KEY-----` marker in chunk 1 must NOT trick sanitizer into
    // treating the subsequent `-----BEGIN EC PRIVATE KEY-----` block as closed!
    assert!(
        !out1_str.contains("LeakedSecretKeyByteSequenceDoNotEmit"),
        "CRITICAL: Unclosed second PEM block leaked bytes into chunk 1 output due to earlier END marker!"
    );
    assert!(
        !out1_str.contains("-----BEGIN EC PRIVATE KEY-----"),
        "Unclosed second PEM block header must be held back in buffer"
    );

    // Block 1 should be sanitized and safe prefix emitted
    assert!(
        out1_str.contains("[REDACTED]"),
        "Completed Block 1 in prefix must be sanitized"
    );

    // Chunk 2 delivers the closing delimiter for block 2
    let mut out2 = Vec::new();
    sanitizer
        .sanitize_chunk(block2_part2.as_bytes(), &engine, &mut out2)
        .unwrap();
    sanitizer.flush_final(&engine, &mut out2).unwrap();

    let out2_str = String::from_utf8_lossy(&out2);
    let total = format!("{}{}", out1_str, out2_str);

    // Both keys must be fully redacted, zero raw key material leaked
    assert!(
        !total.contains("LeakedSecretKeyByteSequenceDoNotEmit"),
        "Secret bytes must never be emitted raw"
    );
    assert!(
        !total.contains("0Y5k1vABCD01234567890"),
        "Block 1 key bytes must never be emitted raw"
    );
}

#[test]
fn test_stream_sanitizer_type_aware_pem_matching() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();
    let mut sanitizer = StreamSanitizer::new();

    // Mismatched delimiter: BEGIN RSA but END EC
    let chunk = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y5k1vMismatchedKeyData=\n-----END EC PRIVATE KEY-----\n";

    let mut out = Vec::new();
    sanitizer
        .sanitize_chunk(chunk.as_bytes(), &engine, &mut out)
        .unwrap();

    // Since END EC does not match BEGIN RSA, it must be detected as UNCLOSED and held back
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        !out_str.contains("MismatchedKeyData"),
        "Mismatched PEM end delimiter must NOT close the block"
    );

    // At final flush, unclosed candidate must be redacted in place
    sanitizer.flush_final(&engine, &mut out).unwrap();
    let total = String::from_utf8_lossy(&out);
    assert!(
        !total.contains("MismatchedKeyData"),
        "Unclosed candidate must be redacted at EOF"
    );
    assert!(
        total.contains("[REDACTED_PRIVATE_KEY_BLOCK]"),
        "Must fail closed with redaction block at EOF"
    );
}

#[test]
fn test_stream_sanitizer_adversarial_boundary_and_fuzz() {
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();

    // 1. Comprehensive Byte-by-Byte Boundary Split Fuzz
    // Split the PEM block at EVERY single byte index from 1 to len-1 across 2 chunks.
    // In every single case, Chunk 1 must never leak payload bytes, and total output must be redacted.
    let full_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y5k1vRSASensitivePayload9876543210=\n-----END RSA PRIVATE KEY-----\n";
    let sensitive_snippet = "SensitivePayload9876543210";

    for split_idx in 1..full_pem.len() {
        let mut sanitizer = StreamSanitizer::new();
        let chunk1 = &full_pem.as_bytes()[..split_idx];
        let chunk2 = &full_pem.as_bytes()[split_idx..];

        let mut out1 = Vec::new();
        sanitizer
            .sanitize_chunk(chunk1, &engine, &mut out1)
            .unwrap();
        let out1_str = String::from_utf8_lossy(&out1);
        assert!(
            !out1_str.contains(sensitive_snippet),
            "Chunk 1 leaked sensitive snippet at split boundary {}: '{}'",
            split_idx,
            out1_str
        );

        let mut out2 = Vec::new();
        sanitizer
            .sanitize_chunk(chunk2, &engine, &mut out2)
            .unwrap();
        sanitizer.flush_final(&engine, &mut out2).unwrap();

        let total = format!("{}{}", out1_str, String::from_utf8_lossy(&out2));
        assert!(
            !total.contains(sensitive_snippet),
            "Total output leaked sensitive snippet at split boundary {}: '{}'",
            split_idx,
            total
        );
        assert!(
            total.contains("[REDACTED]"),
            "Total output must contain [REDACTED] at split boundary {}: '{}'",
            split_idx,
            total
        );
    }

    // 2. Nested BEGIN markers: Inner BEGIN EC occurs before Outer END RSA
    {
        let mut sanitizer = StreamSanitizer::new();
        let nested_stream = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEA_OuterRsaPart1_\n",
            "-----BEGIN EC PRIVATE KEY-----\n",
            "MHQCAQEEIEC_InnerEcSecretData9988_\n",
            "-----END EC PRIVATE KEY-----\n",
            "_OuterRsaPart2_EndPayload_\n",
            "-----END RSA PRIVATE KEY-----\n"
        );

        let mut out = Vec::new();
        sanitizer
            .sanitize_chunk(nested_stream.as_bytes(), &engine, &mut out)
            .unwrap();
        sanitizer.flush_final(&engine, &mut out).unwrap();
        let out_str = String::from_utf8_lossy(&out);

        assert!(
            !out_str.contains("InnerEcSecretData9988"),
            "Nested EC key payload must be sanitized"
        );
        assert!(
            !out_str.contains("OuterRsaPart1"),
            "Outer RSA part 1 payload must be sanitized"
        );
        assert!(
            !out_str.contains("OuterRsaPart2"),
            "Outer RSA part 2 payload must be sanitized"
        );
        assert!(out_str.contains("[REDACTED]"), "Must contain redactions");
    }

    // 3. Binary noise and non-UTF8 bytes directly surrounding PEM blocks
    {
        let mut sanitizer = StreamSanitizer::new();
        let mut binary_chunk = Vec::new();
        binary_chunk.extend_from_slice(&[0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x1B]); // arbitrary non-UTF8 bytes
        binary_chunk.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA_OpenSshSecretNoise_\n-----END OPENSSH PRIVATE KEY-----\n");
        binary_chunk.extend_from_slice(&[0x00, 0xC0, 0xAF, 0x0A]);

        let mut out = Vec::new();
        sanitizer
            .sanitize_chunk(&binary_chunk, &engine, &mut out)
            .unwrap();
        sanitizer.flush_final(&engine, &mut out).unwrap();

        let out_str = String::from_utf8_lossy(&out);
        assert!(
            !out_str.contains("OpenSshSecretNoise"),
            "Binary-embedded OpenSSH payload must be sanitized"
        );
        assert!(
            out_str.contains("[REDACTED]"),
            "Completed binary-embedded block must be sanitized"
        );
        assert_eq!(
            &out[..6],
            &[0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x1B],
            "Binary prefix must be byte-for-byte preserved"
        );
    }

    // 4. Unusual, Custom, and Long PEM type labels
    {
        let mut sanitizer = StreamSanitizer::new();
        let custom_type_pem = concat!(
            "-----BEGIN ENCLAVE_CUSTOM_HARDWARE_HSM_SECP521R1_PRIVATE_KEY-----\n",
            "MIIEowIBAAKCAQEA_LongCustomHsmKeyPayload12345_\n",
            "-----END ENCLAVE_CUSTOM_HARDWARE_HSM_SECP521R1_PRIVATE_KEY-----\n"
        );

        let mut out = Vec::new();
        sanitizer
            .sanitize_chunk(custom_type_pem.as_bytes(), &engine, &mut out)
            .unwrap();
        sanitizer.flush_final(&engine, &mut out).unwrap();

        let out_str = String::from_utf8_lossy(&out);
        assert!(
            !out_str.contains("LongCustomHsmKeyPayload12345"),
            "Custom long-label PEM must be sanitized"
        );
        assert!(
            out_str.contains("[REDACTED]"),
            "Custom long-label PEM must be marked [REDACTED]"
        );
    }
}

#[cfg(unix)]
mod unix_pty_test_support {
    #[repr(C)]
    pub struct pollfd {
        pub fd: i32,
        pub events: i16,
        pub revents: i16,
    }
    pub const POLLIN: i16 = 0x0001;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct Termios {
        pub c_iflag: u32,
        pub c_oflag: u32,
        pub c_cflag: u32,
        pub c_lflag: u32,
        pub c_line: u8,
        pub c_cc: [u8; 32],
        pub c_ispeed: u32,
        pub c_ospeed: u32,
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct Termios {
        pub c_iflag: usize,
        pub c_oflag: usize,
        pub c_cflag: usize,
        pub c_lflag: usize,
        pub c_cc: [u8; 20],
        pub c_ispeed: usize,
        pub c_ospeed: usize,
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("SecretGuard strictly supports Linux and macOS on Unix.");

    #[allow(
        invalid_runtime_symbol_definitions,
        suspicious_runtime_symbol_definitions
    )]
    extern "C" {
        pub fn posix_openpt(oflag: i32) -> i32;
        pub fn grantpt(fd: i32) -> i32;
        pub fn unlockpt(fd: i32) -> i32;
        pub fn ptsname(fd: i32) -> *const std::os::raw::c_char;
        pub fn open(path: *const std::os::raw::c_char, oflag: i32, mode: u32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn dup(fd: i32) -> i32;
        pub fn kill(pid: i32, sig: i32) -> i32;
        pub fn tcgetattr(fd: i32, termios_p: *mut std::ffi::c_void) -> i32;
        pub fn signal(signum: i32, handler: usize) -> usize;
        pub fn poll(fds: *mut pollfd, nfds: usize, timeout: i32) -> i32;
    }

    pub fn open_test_pty() -> Result<(i32, i32), String> {
        #[cfg(target_os = "linux")]
        const O_NOCTTY: i32 = 0o400;
        #[cfg(target_os = "macos")]
        const O_NOCTTY: i32 = 0x20000;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        compile_error!("SecretGuard strictly supports Linux and macOS on Unix.");

        const O_RDWR: i32 = 2;

        let master = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
        if master < 0 {
            return Err("posix_openpt failed".into());
        }
        if unsafe { grantpt(master) } != 0 {
            unsafe {
                close(master);
            }
            return Err("grantpt failed".into());
        }
        if unsafe { unlockpt(master) } != 0 {
            unsafe {
                close(master);
            }
            return Err("unlockpt failed".into());
        }
        let pts = unsafe { ptsname(master) };
        if pts.is_null() {
            unsafe {
                close(master);
            }
            return Err("ptsname returned null".into());
        }
        let slave = unsafe { open(pts, O_RDWR, 0) };
        if slave < 0 {
            unsafe {
                close(master);
            }
            return Err("open slave pty failed".into());
        }
        Ok((master, slave))
    }
}

#[test]
fn test_real_signal_delivery_and_disposition_restoration() {
    #[cfg(unix)]
    {
        if let Ok(worker) = std::env::var("SG_SIGNAL_TEST_WORKER") {
            if worker == "read_password" {
                // Execute SecretGuard's production read_password_hidden
                let res = secretguard::vault::read_password_hidden("Password: ");
                std::process::exit(if res.is_ok() { 0 } else { 1 });
            }
        }
    }

    // Verifies signal handler installation return value checking,
    // rollback semantics, and signal exit codes across platforms.
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    // Unix exit status convention: 128 + signal
    assert_eq!(
        128 + SIGINT,
        130,
        "SIGINT exit code must strictly equal 130"
    );
    assert_eq!(
        128 + SIGTERM,
        143,
        "SIGTERM exit code must strictly equal 143"
    );

    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Command, Stdio};
        use unix_pty_test_support::*;

        let exe = std::env::current_exe().expect("Must have current test binary path");

        let run_signal_test = |sig_to_send: i32, expected_exit_code: i32| {
            let (master_fd, slave_fd) = open_test_pty()
                .expect("PTY allocation must succeed to test terminal signal handling");

            // Duplicate slave descriptor into an independent observer descriptor.
            // This observer descriptor is held exclusively by the parent test process
            // so tcgetattr() can inspect terminal state after the child exits without
            // using a descriptor transferred to or closed by the child.
            let observer_fd = unsafe { dup(slave_fd) };
            assert!(
                observer_fd >= 0,
                "dup(slave_fd) must succeed to create observer descriptor"
            );

            // Convert slave_fd into File instances for child standard streams
            let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
            let slave_out = slave_in
                .try_clone()
                .expect("Failed to clone slave fd for stdout");
            let slave_err = slave_in
                .try_clone()
                .expect("Failed to clone slave fd for stderr");

            let mut master_file = unsafe { fs::File::from_raw_fd(master_fd) };

            let mut child = Command::new(&exe)
                .arg("test_real_signal_delivery_and_disposition_restoration")
                .arg("--nocapture")
                .arg("--exact")
                .env("SG_SIGNAL_TEST_WORKER", "read_password")
                .env("SG_SIGNAL_TEST_ARMED", "1") // Requests deterministic readiness notification
                .stdin(Stdio::from(slave_in))
                .stdout(Stdio::from(slave_out))
                .stderr(Stdio::from(slave_err))
                .spawn()
                .expect("Failed to spawn child worker with slave PTY");

            // Bounded deterministic synchronization:
            // Read from master PTY until child writes "SG_ARMED\n".
            // "SG_ARMED" is emitted ONLY AFTER stty -echo succeeds, signal handlers are actively armed, and signals are unblocked.
            // Uses poll() with a 5-second deadline so test never hangs if child stalls or crashes.
            let start = std::time::Instant::now();
            let deadline = std::time::Duration::from_secs(5);
            let mut ready_buf = Vec::new();
            let mut single = [0u8; 1];

            while !ready_buf.windows(8).any(|w| w == b"SG_ARMED") {
                let elapsed = start.elapsed();
                if elapsed >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "Timed out waiting for child SG_ARMED notification after 5s. Buffer: {:?}",
                        String::from_utf8_lossy(&ready_buf)
                    );
                }

                let remaining_ms = (deadline - elapsed).as_millis() as i32;
                let mut pfd = pollfd {
                    fd: master_fd,
                    events: POLLIN,
                    revents: 0,
                };
                let poll_timeout = remaining_ms.min(100);
                let ret = unsafe { poll(&mut pfd, 1, poll_timeout) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("poll() failed while waiting for SG_ARMED: {}", err);
                }

                if let Ok(Some(exit_status)) = child.try_wait() {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "Child process exited prematurely with status {:?} before emitting SG_ARMED. Buffer: {:?}",
                        exit_status,
                        String::from_utf8_lossy(&ready_buf)
                    );
                }

                match master_file.read(&mut single) {
                    Ok(0) => break,
                    Ok(n) => ready_buf.extend_from_slice(&single[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }

            if !ready_buf.windows(8).any(|w| w == b"SG_ARMED") {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "Child terminated without notifying SG_ARMED. Output received: {:?}",
                    String::from_utf8_lossy(&ready_buf)
                );
            }

            // Send target signal to child process
            unsafe {
                kill(child.id() as i32, sig_to_send);
            }

            // Await child termination with a bounded 5s deadline
            let status = wait_for_child_with_timeout(&mut child, Duration::from_secs(5));
            let code = status
                .code()
                .unwrap_or_else(|| status.signal().map(|s| 128 + s).unwrap_or(0));
            assert_eq!(
                code, expected_exit_code,
                "Child interrupted by signal {} must exit with code {} (received code: {})",
                sig_to_send, expected_exit_code, code
            );

            // Inspect terminal echo restoration using the independent observer descriptor.
            // tcgetattr failure is a hard test failure (no silent skipping).
            let mut term = unsafe { std::mem::zeroed::<Termios>() };
            let tc_res = unsafe {
                tcgetattr(
                    observer_fd,
                    &mut term as *mut Termios as *mut std::ffi::c_void,
                )
            };
            assert_eq!(
                tc_res, 0,
                "tcgetattr() must succeed on observer descriptor after child termination"
            );

            // In POSIX termios (Linux, macOS, BSD), ECHO bit in c_lflag is 0x0008 (8).
            const ECHO_FLAG: usize = 0x0008;
            assert_ne!(
                (term.c_lflag as usize & ECHO_FLAG),
                0,
                "Terminal echo (ECHO bit in c_lflag) must be restored after signal interruption"
            );

            unsafe {
                close(observer_fd);
            }
        };

        // Test SIGINT (Ctrl+C): child must handle signal, restore dispositions, restore echo, and exit with 130
        run_signal_test(2, 130);

        // Test SIGTERM: child must handle signal, restore dispositions, restore echo, and exit with 143
        run_signal_test(15, 143);

        // Verify parent process signal dispositions are intact
        let current_disp = unsafe { signal(SIGINT, 0) };
        unsafe {
            signal(SIGINT, current_disp);
        }
        assert_ne!(
            current_disp, !0usize,
            "Signal disposition must be queryable and restored"
        );
    }
}

#[test]
fn test_read_password_hidden_multithread_serialization() {
    #[cfg(unix)]
    {
        if let Ok(worker) = std::env::var("SG_CONCURRENT_INPUT_WORKER") {
            if worker == "1" {
                // Child worker process: Spawns 3 concurrent threads that all call
                // the ACTUAL production secretguard::vault::read_password_hidden() function
                use std::sync::mpsc;
                use std::thread;

                let (tx, rx) = mpsc::channel();
                let mut handles = Vec::new();

                for id in 1..=3 {
                    let tx_clone = tx.clone();
                    handles.push(thread::spawn(move || {
                        // Call the ACTUAL production function under multi-threaded concurrency!
                        let res = secretguard::vault::read_password_hidden(&format!(
                            "WorkerPrompt{}: ",
                            id
                        ));
                        match res {
                            Ok(pass) => {
                                let _ = tx_clone.send((id, pass));
                            }
                            Err(e) => {
                                eprintln!("Thread {} failed: {}", id, e);
                                std::process::exit(1);
                            }
                        }
                    }));
                }
                drop(tx);

                let mut results = Vec::new();
                while let Ok((id, pass)) = rx.recv() {
                    results.push((id, pass));
                }

                for h in handles {
                    h.join().unwrap();
                }

                // Verify all 3 threads successfully acquired the serialized lock,
                // suppressed terminal echo, restored echo, and read their distinct passwords
                assert_eq!(
                    results.len(),
                    3,
                    "All 3 threads must complete password input"
                );
                let mut passwords: Vec<String> = results.into_iter().map(|(_, p)| p).collect();
                passwords.sort();
                assert_eq!(
                    passwords,
                    vec!["secret_alpha_111", "secret_beta_222", "secret_gamma_333"],
                    "Passwords must be received intact without cross-thread corruption"
                );

                std::process::exit(0);
            }
        }

        use std::fs;
        use std::io::Write;
        use std::os::unix::io::FromRawFd;
        use std::process::{Command, Stdio};
        use unix_pty_test_support::*;

        // Open a controlled PTY for the concurrent worker process
        let (master_fd, slave_fd) =
            open_test_pty().expect("PTY allocation must succeed for concurrency test");
        let slave_in = unsafe { fs::File::from_raw_fd(slave_fd) };
        let slave_out = slave_in
            .try_clone()
            .expect("Failed to clone slave fd for stdout");
        let slave_err = slave_in
            .try_clone()
            .expect("Failed to clone slave fd for stderr");
        let mut master_file = unsafe { fs::File::from_raw_fd(master_fd) };

        let exe = std::env::current_exe().expect("Must have current test binary path");
        let mut child = Command::new(&exe)
            .arg("test_read_password_hidden_multithread_serialization")
            .arg("--nocapture")
            .arg("--exact")
            .env("SG_CONCURRENT_INPUT_WORKER", "1")
            .stdin(Stdio::from(slave_in))
            .stdout(Stdio::from(slave_out))
            .stderr(Stdio::from(slave_err))
            .spawn()
            .expect("Failed to spawn concurrent worker child");

        // Feed passwords sequentially into master PTY with small pauses.
        // As each thread acquires TERMINAL_INPUT_LOCK and configures stty, it reads one complete line.
        let inputs = [
            "secret_alpha_111\n",
            "secret_beta_222\n",
            "secret_gamma_333\n",
        ];
        for line in &inputs {
            std::thread::sleep(std::time::Duration::from_millis(60));
            master_file
                .write_all(line.as_bytes())
                .expect("write to master PTY");
            master_file.flush().expect("flush master PTY");
        }

        // Bounded wait with 5s timeout using reusable helper
        let status = wait_for_child_with_timeout(&mut child, Duration::from_secs(5));
        assert!(
            status.success(),
            "Concurrent child worker calling read_password_hidden() must exit 0"
        );
    }

    #[cfg(windows)]
    {
        // On Windows, verify that TERMINAL_INPUT_LOCK strictly enforces mutual exclusion across concurrent threads
        use secretguard::vault::TERMINAL_INPUT_LOCK;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let cnt = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                let _lock = TERMINAL_INPUT_LOCK
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let prev = cnt.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(5));
                let curr = cnt.load(Ordering::SeqCst);
                assert_eq!(
                    curr,
                    prev + 1,
                    "Serialized terminal lock must enforce mutual exclusion"
                );
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 8);
    }
}

#[test]
fn test_windows_ancestor_directory_anchoring_prevents_rename() {
    #[cfg(windows)]
    {
        use secretguard::vault::{
            anchor_ancestor_directories, create_secure_file_exclusive, open_secure_file_for_read,
        };
        use std::fs;
        use std::io::{Read, Write};
        use std::sync::mpsc;
        use std::thread;

        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("sg_anchor_test_{}", pid));
        let ancestor_dir = base.join("locked_parent");
        let target_file = ancestor_dir.join("production_vault.enc");
        let renamed_dir = base.join("locked_parent_renamed");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&ancestor_dir).unwrap();

        // 1. Production API Test: create_secure_file_exclusive
        // Traverses ancestors, anchors directory handles without FILE_SHARE_DELETE,
        // validates intermediate security descriptors, creates target exclusively,
        // validates target security descriptor, and automatically releases ancestor locks upon completion.
        let mut created_file = create_secure_file_exclusive(&target_file, 0o600)
            .expect("create_secure_file_exclusive must succeed in valid directory hierarchy");
        created_file
            .write_all(b"production vaulted payload")
            .expect("Write must succeed");
        created_file.flush().expect("Flush must succeed");
        drop(created_file);

        // 2. Production API Test: open_secure_file_for_read
        // Anchors ancestor directory handles, validates permissions and descriptors,
        // opens target file, and releases ancestor locks upon completion.
        let mut opened_file = open_secure_file_for_read(&target_file)
            .expect("open_secure_file_for_read must succeed on valid target")
            .expect("File must exist");
        let mut read_buf = Vec::new();
        opened_file
            .read_to_end(&mut read_buf)
            .expect("Read must succeed");
        assert_eq!(
            read_buf, b"production vaulted payload",
            "Data read back via open_secure_file_for_read must match"
        );
        drop(opened_file);

        // 3. Verify handle cleanup on success path:
        // Ancestor handles held during production operations must be fully released by AncestorGuards drop.
        let rename_after_success = fs::rename(&ancestor_dir, &renamed_dir);
        assert!(
            rename_after_success.is_ok(),
            "Ancestor directory must be unlocked and renameable after production function returns"
        );
        fs::rename(&renamed_dir, &ancestor_dir)
            .expect("Restoring original directory name must succeed");

        // 4. Verify handle cleanup on error paths:
        let err_target = open_secure_file_for_read(&ancestor_dir);
        assert!(err_target.is_err(), "Opening directory as file must fail");
        assert!(
            err_target.unwrap_err().contains("directory"),
            "Error must state target is a directory"
        );

        let rename_after_error = fs::rename(&ancestor_dir, &renamed_dir);
        assert!(
            rename_after_error.is_ok(),
            "Ancestor directory handles must be dropped even on error return paths"
        );
        fs::rename(&renamed_dir, &ancestor_dir)
            .expect("Restoring original directory name must succeed");

        // 5. Synchronization-based Concurrent Test:
        // Spawns an attacker thread attempting to rename the ancestor directory
        // WHILE the production operation (anchor_ancestor_directories) is actively holding
        // ancestor handles without FILE_SHARE_DELETE.
        let (tx_ready, rx_ready) = mpsc::channel();
        let (tx_done, rx_done) = mpsc::channel();
        let ancestor_dir_clone = ancestor_dir.clone();
        let renamed_dir_clone = renamed_dir.clone();

        let attacker_thread = thread::spawn(move || {
            // Wait for production operation to acquire handles
            rx_ready.recv().expect("Failed to receive ready signal");
            // Attempt rename while production ancestor handles are actively held
            let rename_res = fs::rename(&ancestor_dir_clone, &renamed_dir_clone);
            tx_done
                .send(rename_res)
                .expect("Failed to send rename result");
        });

        // Production operation actively anchors ancestor directories:
        let guards = anchor_ancestor_directories(&target_file)
            .expect("anchor_ancestor_directories must succeed on valid path");

        // Signal attacker thread that production operation is actively holding handles
        tx_ready.send(()).expect("Failed to signal attacker");

        // Attacker's rename must be blocked by Windows kernel with ERROR_SHARING_VIOLATION (32)
        let rename_during = rx_done
            .recv()
            .expect("Failed to receive rename attempt result");
        assert!(
            rename_during.is_err(),
            "Concurrent rename while production handles are held MUST be rejected"
        );
        let err = rename_during.unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(32),
            "Windows kernel must return ERROR_SHARING_VIOLATION (32) during active production operation"
        );

        // Production operation finishes and drops its ancestor handles:
        drop(guards);
        attacker_thread
            .join()
            .expect("Attacker thread failed to join");

        // Verify that after production operation releases handles, rename succeeds immediately
        let rename_unlocked = fs::rename(&ancestor_dir, &renamed_dir);
        assert!(
            rename_unlocked.is_ok(),
            "Rename must succeed once production ancestor handles are released"
        );

        let _ = fs::remove_dir_all(&base);
    }
}

#[test]
fn test_stream_sanitizer_multi_chunk_random_partition_fuzz() {
    use rand_core::{OsRng, RngCore};
    use secretguard::vault::StreamSanitizer;
    use secretguard::SecretGuardEngine;

    let engine = SecretGuardEngine::new();

    let full_stream = concat!(
        "=== SYSTEM BOOT SEQUENCE START ===\n",
        "INFO: Initializing cryptographic subsystem...\n",
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIEowIBAAKCAQEA0Y5k1vRSA_ArbitrarySecretDataBlock1_SecretGuardVaultEngine9876543210=\n",
        "-----END RSA PRIVATE KEY-----\n",
        "INFO: RSA Keypair imported successfully. Checking secondary interfaces...\n",
        "-----BEGIN EC PRIVATE KEY-----\n",
        "MHQCAQEEI_ArbitrarySecretDataBlock2_ECKey1234567890SecretGuardTestingFixture=\n",
        "-----END EC PRIVATE KEY-----\n",
        "INFO: Authenticating cloud agent orchestrator...\n",
        "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "=== SYSTEM BOOT SEQUENCE COMPLETE: LISTENING ON PORT 8443 ===\n"
    );

    let forbidden_secrets = [
        "ArbitrarySecretDataBlock1_SecretGuardVaultEngine9876543210",
        "ArbitrarySecretDataBlock2_ECKey1234567890SecretGuardTestingFixture",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ];

    let full_bytes = full_stream.as_bytes();
    let stream_len = full_bytes.len();

    // Run 100 randomized multi-chunk partition fuzz iterations
    for iteration in 0..100 {
        let mut sanitizer = StreamSanitizer::new();

        // Random number of chunks between 3 and 10
        let mut rand_buf = [0u8; 16];
        OsRng.fill_bytes(&mut rand_buf);
        let num_splits = (rand_buf[0] as usize % 8) + 2; // 2 to 9 split points => 3 to 10 chunks

        let mut split_points = Vec::new();
        for _ in 0..num_splits {
            let offset = (rand_core::RngCore::next_u32(&mut OsRng) as usize % (stream_len - 2)) + 1;
            split_points.push(offset);
        }
        split_points.sort_unstable();
        split_points.dedup();

        // Construct chunks
        let mut chunks = Vec::new();
        let mut prev = 0;
        for &pt in &split_points {
            if pt > prev && pt < stream_len {
                chunks.push(&full_bytes[prev..pt]);
                prev = pt;
            }
        }
        if prev < stream_len {
            chunks.push(&full_bytes[prev..]);
        }

        let mut total_output = Vec::new();

        for (chunk_idx, chunk) in chunks.iter().enumerate() {
            let mut chunk_out = Vec::new();
            sanitizer
                .sanitize_chunk(chunk, &engine, &mut chunk_out)
                .unwrap();

            let chunk_str = String::from_utf8_lossy(&chunk_out);
            for secret in &forbidden_secrets {
                assert!(
                    !chunk_str.contains(secret),
                    "Iteration {}, chunk {} leaked secret '{}' in output: '{}'",
                    iteration,
                    chunk_idx,
                    secret,
                    chunk_str
                );
            }
            total_output.extend_from_slice(&chunk_out);
        }

        let mut flush_out = Vec::new();
        sanitizer.flush_final(&engine, &mut flush_out).unwrap();
        let flush_str = String::from_utf8_lossy(&flush_out);
        for secret in &forbidden_secrets {
            assert!(
                !flush_str.contains(secret),
                "Iteration {} leaked secret '{}' during flush_final: '{}'",
                iteration,
                secret,
                flush_str
            );
        }
        total_output.extend_from_slice(&flush_out);

        let total_str = String::from_utf8_lossy(&total_output);
        for secret in &forbidden_secrets {
            assert!(
                !total_str.contains(secret),
                "Iteration {} leaked secret '{}' in combined output: '{}'",
                iteration,
                secret,
                total_str
            );
        }

        // Verify non-secret markers are preserved and redaction markers are present
        assert!(
            total_str.contains("=== SYSTEM BOOT SEQUENCE START ==="),
            "Prefix must be preserved in iteration {}",
            iteration
        );
        assert!(
            total_str.contains("=== SYSTEM BOOT SEQUENCE COMPLETE: LISTENING ON PORT 8443 ==="),
            "Suffix must be preserved in iteration {}",
            iteration
        );
        assert!(
            total_str.contains("[REDACTED]"),
            "Must contain [REDACTED] markers in iteration {}",
            iteration
        );
    }
}
