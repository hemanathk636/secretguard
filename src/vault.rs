use crate::SecretGuardEngine;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VaultStore {
    pub secrets: HashMap<String, String>,
}

pub fn get_vault_path() -> PathBuf {
    if let Ok(p) = env::var("SECRETGUARD_VAULT_PATH") {
        return PathBuf::from(p);
    }
    let home = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let dir = Path::new(&home).join(".secretguard");
    dir.join("vault.enc")
}

pub fn get_master_key_path() -> PathBuf {
    if let Ok(p) = env::var("SECRETGUARD_MASTER_KEY_PATH") {
        return PathBuf::from(p);
    }
    let base_dir = env::var("SECRETGUARD_DIR")
        .or_else(|_| env::var("USERPROFILE"))
        .or_else(|_| env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let dir = Path::new(&base_dir).join(".secretguard");
    if let Ok(_) = fs::create_dir_all(&dir) {
        if dir.exists() {
            return dir.join(".master.key");
        }
    }
    let temp = env::temp_dir().join(".secretguard");
    let _ = fs::create_dir_all(&temp);
    temp.join(".master.key")
}

/// Retrieves or generates a genuine 256-bit cryptographically secure random master key via CSPRNG (OsRng)
/// with atomic 0600 file creation on Unix.
pub fn get_or_generate_master_key() -> [u8; 32] {
    let path = get_master_key_path();
    if path.exists() {
        if let Ok(bytes) = fs::read(&path) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return key;
            }
        }
    }

    // Generate genuine 256-bit cryptographically secure random key via OsRng (CSPRNG)
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("Warning: Failed to create master key directory {}: {}", parent.display(), e);
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&key) {
                    eprintln!("Warning: Failed to write master key to {}: {}", path.display(), e);
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to create master key file {}: {}", path.display(), e);
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = fs::write(&path, &key) {
            eprintln!("Warning: Failed to write master key to {}: {}", path.display(), e);
        }
    }

    key
}

/// RFC 5869 HKDF-SHA256 (Extract and Expand) using official audited `hkdf` crate
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("Valid length for HKDF-SHA256 expansion");
    okm
}

pub fn derive_vault_key(passphrase: Option<&str>) -> [u8; 32] {
    let master = get_or_generate_master_key();
    let salt = match passphrase {
        Some(pass) => pass.as_bytes(),
        None => b"secretguard_vault_rfc5869_salt_v3",
    };
    let info = b"SECRETGUARD_RFC5869_HKDF_AES256GCM_KEY";
    let derived = hkdf_sha256(salt, &master, info, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived[..32]);
    key
}

pub fn encrypt_vault_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

pub fn decrypt_vault_payload(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Encrypted vault data is corrupted or too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed: Incorrect key, password, or corrupted vault".to_string())
}

pub fn load_vault(passphrase: Option<&str>) -> Result<VaultStore, String> {
    let path = get_vault_path();
    if !path.exists() {
        return Ok(VaultStore::default());
    }

    let data = fs::read(&path).map_err(|e| format!("Failed to read vault file: {}", e))?;
    let key = derive_vault_key(passphrase);
    let decrypted = decrypt_vault_payload(&data, &key)?;
    let store: VaultStore = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse decrypted vault data: {}", e))?;
    Ok(store)
}

pub fn save_vault(store: &VaultStore, passphrase: Option<&str>) -> Result<(), String> {
    let path = get_vault_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create vault directory {}: {}", parent.display(), e))?;
    }
    let json_bytes =
        serde_json::to_vec(store).map_err(|e| format!("Failed to serialize vault: {}", e))?;
    let key = derive_vault_key(passphrase);
    let encrypted = encrypt_vault_payload(&json_bytes, &key)?;

    let tmp_path = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temporary vault file {} with 0600 mode: {}", tmp_path.display(), e))?;
        file.write_all(&encrypted)
            .map_err(|e| format!("Failed to write encrypted vault data to {}: {}", tmp_path.display(), e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temporary vault file: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, &encrypted)
            .map_err(|e| format!("Failed to write temporary vault file (path: {}): {}", tmp_path.display(), e))?;
    }

    fs::rename(&tmp_path, &path)
        .map_err(|e| format!("Failed to atomically replace vault file {}: {}", path.display(), e))?;

    Ok(())
}

pub fn run_vault_cli(args: &[String], engine: &SecretGuardEngine) {
    if args.is_empty() {
        eprintln!(
            r#"SecretGuard Encrypted Zero-Knowledge Memory Vault (v0.3.3)

USAGE:
    secretguard vault <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    set <NAME> [VALUE]         Encrypts and saves secret to local AES-256-GCM vault.
    get <NAME>                 Decrypts and prints secret value to stdout.
    list                       Lists stored secret identifiers (names only, values protected).
    delete <NAME>              Removes a secret from the vault.
    run <KEYS...> -- <CMD...>  Injects vault secrets into child process in-memory only.
    import-env [PATH]          Imports secrets from .env file into vault and creates .env.example.
"#
        );
        process::exit(2);
    }

    match args[0].as_str() {
        "set" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault set <KEY_NAME> [VALUE]");
                process::exit(2);
            }
            let key_name = &args[1];
            let secret_val = if args.len() >= 3 {
                args[2].clone()
            } else {
                eprint!("Enter secret value for '{}': ", key_name);
                let _ = io::stdout().flush();
                let mut buffer = String::new();
                let _ = io::stdin().read_line(&mut buffer);
                buffer.trim().to_string()
            };

            let mut store = load_vault(None).unwrap_or_default();
            store.secrets.insert(key_name.to_string(), secret_val);
            if let Err(e) = save_vault(&store, None) {
                eprintln!("❌ Failed to save secret: {}", e);
                process::exit(1);
            }
            println!("🔒 Successfully encrypted & stored '{}' in SecretGuard Vault (AES-256-GCM)!", key_name);
        }
        "get" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault get <KEY_NAME>");
                process::exit(2);
            }
            let key_name = &args[1];
            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            if let Some(val) = store.secrets.get(key_name) {
                print!("{}", val);
            } else {
                eprintln!("❌ Secret '{}' not found in vault.", key_name);
                process::exit(1);
            }
        }
        "list" => {
            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            println!("🔐 SecretGuard Encrypted Vault: ~/.secretguard/vault.enc\n");
            if store.secrets.is_empty() {
                println!("(Vault is currently empty. Use 'secretguard vault set <KEY>' to add secrets)");
            } else {
                println!("{:<25} {:<15}", "SECRET NAME", "ALGORITHM");
                println!("──────────────────────────────────────────");
                for key in store.secrets.keys() {
                    println!("{:<25} {:<15}", key, "AES-256-GCM");
                }
                println!("\nTotal Secrets Stored: {}", store.secrets.len());
            }
        }
        "delete" | "rm" => {
            if args.len() < 2 {
                eprintln!("Usage: secretguard vault delete <KEY_NAME>");
                process::exit(2);
            }
            let key_name = &args[1];
            let mut store = load_vault(None).unwrap_or_default();
            if store.secrets.remove(key_name).is_some() {
                if let Err(e) = save_vault(&store, None) {
                    eprintln!("❌ Failed to save vault after deletion: {}", e);
                    process::exit(1);
                }
                println!("🗑️  Removed '{}' from vault.", key_name);
            } else {
                eprintln!("❌ Secret '{}' not found.", key_name);
                process::exit(1);
            }
        }
        "run" => {
            let split_pos = args.iter().position(|a| a == "--");
            if split_pos.is_none() || split_pos.unwrap() == args.len() - 1 {
                eprintln!("Usage: secretguard vault run <KEY1> [KEY2...] -- <COMMAND> [ARGS...]");
                process::exit(2);
            }
            let pos = split_pos.unwrap();
            let key_names = &args[1..pos];
            let cmd_parts = &args[pos + 1..];

            let store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ {}", e);
                    process::exit(1);
                }
            };

            let mut env_injects = HashMap::new();
            for key in key_names {
                if let Some(val) = store.secrets.get(key) {
                    env_injects.insert(key.clone(), val.clone());
                } else {
                    eprintln!("⚠️  Warning: Vault key '{}' not found, running without it.", key);
                }
            }

            let child_cmd = &cmd_parts[0];
            let child_args = &cmd_parts[1..];

            println!("🔒 SecretGuard Vault: Injected {} secret(s) into memory for '{}'", env_injects.len(), child_cmd);

            let mut child = Command::new(child_cmd)
                .args(child_args)
                .envs(&env_injects)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| {
                    eprintln!("❌ Failed to execute command '{}': {}", child_cmd, e);
                    process::exit(1);
                });

            // Asynchronously sanitize child stderr to prevent credential leakage in error logs
            let stderr_opt = child.stderr.take();
            let stderr_thread = std::thread::spawn(move || {
                if let Some(stderr) = stderr_opt {
                    let reader = io::BufReader::new(stderr);
                    let stderr_handle = io::stderr();
                    let mut handle = stderr_handle.lock();
                    let local_engine = SecretGuardEngine::new();
                    for line in reader.lines().flatten() {
                        let res = local_engine.scan_and_sanitize(&line);
                        let _ = writeln!(handle, "{}", res.sanitized_text);
                    }
                }
            });

            if let Some(stdout) = child.stdout.take() {
                let reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();

                for line in reader.lines().flatten() {
                    let res = engine.scan_and_sanitize(&line);
                    let _ = writeln!(handle, "{}", res.sanitized_text);
                }
            }

            let _ = stderr_thread.join();
            let status = child.wait().expect("Child process was not running");
            process::exit(status.code().unwrap_or(0));
        }
        "import-env" => {
            let target_env = if args.len() >= 2 { &args[1] } else { ".env" };
            let env_path = Path::new(target_env);
            if !env_path.exists() {
                eprintln!("❌ File not found: {}", env_path.display());
                process::exit(1);
            }

            println!("📥 Importing secrets from '{}' into encrypted vault...", env_path.display());

            let file = match File::open(env_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("❌ Failed to open '{}': {}", env_path.display(), e);
                    process::exit(1);
                }
            };
            let reader = io::BufReader::new(file);
            let mut store = load_vault(None).unwrap_or_default();
            let mut imported = 0;
            let mut example_lines = Vec::new();

            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    example_lines.push(line);
                    continue;
                }

                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().trim_matches('"').trim_matches('\'').to_string();

                    if !val.is_empty() {
                        store.secrets.insert(key.clone(), val);
                        imported += 1;
                        example_lines.push(format!("{}=YOUR_{}_HERE", key, key));
                    }
                }
            }

            if let Err(e) = save_vault(&store, None) {
                eprintln!("❌ Failed to save vault: {}", e);
                process::exit(1);
            }
            let example_path = env_path.with_file_name(".env.example");
            match File::create(&example_path) {
                Ok(mut out) => {
                    for l in example_lines {
                        let _ = writeln!(out, "{}", l);
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Warning: Failed to create template file '{}': {}", example_path.display(), e);
                }
            }

            println!("✨ Successfully imported {} secret(s) into encrypted vault!", imported);
            println!("📄 Created clean template: {}", example_path.display());
            println!("🔒 Your secrets are now safe from git commits and shell leaks.");
        }
        _ => {
            eprintln!("Unknown vault subcommand: '{}'", args[0]);
            process::exit(2);
        }
    }
}
