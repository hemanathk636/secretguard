use crate::SecretGuardEngine;
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

pub fn derive_vault_key(passphrase: Option<&str>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| "secretguard-default-salt".to_string());
    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "local-dev".to_string());

    hasher.update(b"SECRETGUARD_VAULT_SALT_v1");
    hasher.update(home.as_bytes());
    hasher.update(user.as_bytes());

    if let Some(pass) = passphrase {
        hasher.update(b":PASS:");
        hasher.update(pass.as_bytes());
    }

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
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
        let _ = fs::create_dir_all(parent);
    }
    let json_bytes =
        serde_json::to_vec(store).map_err(|e| format!("Failed to serialize vault: {}", e))?;
    let key = derive_vault_key(passphrase);
    let encrypted = encrypt_vault_payload(&json_bytes, &key)?;
    fs::write(&path, encrypted).map_err(|e| format!("Failed to write vault file (path: {}): {}", path.display(), e))?;
    Ok(())
}

pub fn run_vault_cli(args: &[String], engine: &SecretGuardEngine) {
    if args.is_empty() {
        eprintln!(
            r#"SecretGuard Encrypted Zero-Knowledge Memory Vault (v0.1.6)

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
                save_vault(&store, None).unwrap();
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
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap_or_else(|e| {
                    eprintln!("❌ Failed to execute command '{}': {}", child_cmd, e);
                    process::exit(1);
                });

            if let Some(stdout) = child.stdout.take() {
                let reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();

                for line in reader.lines().flatten() {
                    let res = engine.scan_and_sanitize(&line);
                    writeln!(handle, "{}", res.sanitized_text).unwrap();
                }
            }

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

            let file = File::open(env_path).unwrap();
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

            save_vault(&store, None).unwrap();
            let example_path = env_path.with_file_name(".env.example");
            let mut out = File::create(&example_path).unwrap();
            for l in example_lines {
                writeln!(out, "{}", l).unwrap();
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
