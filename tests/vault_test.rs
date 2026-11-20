use secretguard::vault::{
    decrypt_vault_payload, derive_vault_key, encrypt_vault_payload, VaultStore,
};

#[test]
fn test_vault_aes_gcm_roundtrip() {
    let key = derive_vault_key(Some("test-passphrase-123"));
    let plaintext = b"sk-proj-super-secret-production-openai-key";

    let encrypted = encrypt_vault_payload(plaintext, &key).expect("Encryption failed");
    assert_ne!(encrypted, plaintext);
    assert!(encrypted.len() > plaintext.len()); // Nonce + Auth Tag + Ciphertext

    let decrypted = decrypt_vault_payload(&encrypted, &key).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_vault_wrong_key_fails() {
    let key1 = derive_vault_key(Some("correct-key"));
    let key2 = derive_vault_key(Some("wrong-key"));
    let plaintext = b"my-private-database-password";

    let encrypted = encrypt_vault_payload(plaintext, &key1).unwrap();
    let result = decrypt_vault_payload(&encrypted, &key2);

    assert!(result.is_err());
}

#[test]
fn test_vault_store_serialization() {
    let mut store = VaultStore::default();
    store
        .secrets
        .insert("OPENAI_KEY".to_string(), "sk-1234567890".to_string());
    store
        .secrets
        .insert("STRIPE_KEY".to_string(), "sk_live_998877".to_string());

    let json = serde_json::to_vec(&store).unwrap();
    let key = derive_vault_key(None);
    let enc = encrypt_vault_payload(&json, &key).unwrap();
    let dec = decrypt_vault_payload(&enc, &key).unwrap();
    let loaded: VaultStore = serde_json::from_slice(&dec).unwrap();

    assert_eq!(loaded.secrets.len(), 2);
    assert_eq!(loaded.secrets.get("OPENAI_KEY").unwrap(), "sk-1234567890");
    assert_eq!(loaded.secrets.get("STRIPE_KEY").unwrap(), "sk_live_998877");
}
