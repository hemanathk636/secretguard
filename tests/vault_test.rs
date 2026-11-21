use secretguard::vault::{
    decrypt_vault_payload, derive_vault_key, encrypt_vault_payload, get_or_generate_master_key,
    load_vault, save_vault, VaultStore,
};
use std::fs;
use std::sync::Mutex;

static VAULT_TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_vault_aes_gcm_roundtrip() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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

    // Stream 2KB of non-secret filler text
    let filler = vec![b'A'; 1500];
    let mut out1 = Vec::new();
    sanitizer.sanitize_chunk(&filler, &engine, &mut out1).unwrap();
    // out1 should have drained 1500 - 1024 = 476 bytes
    assert_eq!(out1.len(), 1500 - StreamSanitizer::WINDOW_SIZE);

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
