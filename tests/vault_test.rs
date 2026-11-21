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
    let key = derive_vault_key(Some("test-passphrase-123")).expect("Key derivation failed");
    let plaintext = b"sk-proj-super-secret-production-openai-key";

    let encrypted = encrypt_vault_payload(plaintext, &key).expect("Encryption failed");
    assert_ne!(encrypted, plaintext);
    assert!(encrypted.len() > plaintext.len()); // Nonce + Auth Tag + Ciphertext

    let decrypted = decrypt_vault_payload(&encrypted, &key).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_vault_wrong_key_fails() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
    let key1 = derive_vault_key(Some("correct-key")).expect("Key derivation failed");
    let key2 = derive_vault_key(Some("wrong-key")).expect("Key derivation failed");
    let plaintext = b"my-private-database-password";

    let encrypted = encrypt_vault_payload(plaintext, &key1).unwrap();
    let result = decrypt_vault_payload(&encrypted, &key2);

    assert!(result.is_err());
}

#[test]
fn test_vault_store_serialization() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
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
}

#[test]
fn test_corrupted_vault_file_fails_loudly_without_data_loss() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sg_vault_corrupt_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let corrupt_vault_path = temp_dir.join("vault.enc");

    // Write bogus corrupted ciphertext
    fs::write(&corrupt_vault_path, b"not_valid_aes_gcm_ciphertext_at_all").unwrap();

    std::env::set_var("SECRETGUARD_VAULT_PATH", &corrupt_vault_path);

    // Attempting to load MUST return Err, NEVER unwrap_or_default
    let result = load_vault(None);
    assert!(result.is_err(), "Loading a corrupted vault MUST fail with Err to prevent overwriting existing data");

    // Cleanup
    std::env::remove_var("SECRETGUARD_VAULT_PATH");
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

    std::env::set_var("SECRETGUARD_MASTER_KEY_PATH", &corrupt_key_path);

    let result = get_or_generate_master_key();
    assert!(result.is_err(), "Truncated master key must be rejected to prevent vault orphaning");
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("corrupted"), "Error should explain key corruption: {}", err_msg);

    // Cleanup
    std::env::remove_var("SECRETGUARD_MASTER_KEY_PATH");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_atomic_unique_tmp_file_during_save_vault() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sg_save_atomic_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let vault_path = temp_dir.join("vault.enc");

    std::env::set_var("SECRETGUARD_VAULT_PATH", &vault_path);

    let mut store = VaultStore::default();
    store.secrets.insert("PROD_DB".to_string(), "postgres://user:pass@db:5432/prod".to_string());

    let save_res = save_vault(&store, None);
    assert!(save_res.is_ok(), "save_vault should succeed with unique tmp file");
    assert!(vault_path.exists(), "Final vault file must exist after atomic rename");

    // Verify temp files were cleanly cleaned up
    let entries: Vec<_> = fs::read_dir(&temp_dir).unwrap().filter_map(|e| e.ok()).collect();
    assert_eq!(entries.len(), 1, "Only final vault file should remain; temporary files must be cleaned up");

    std::env::remove_var("SECRETGUARD_VAULT_PATH");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_windows_and_unix_existing_vault_replacement() {
    let _lock = VAULT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("sg_replace_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let vault_path = temp_dir.join("vault.enc");

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
    let _ = fs::remove_dir_all(&temp_dir);
}
