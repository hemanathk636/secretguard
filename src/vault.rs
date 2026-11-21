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

/// Resolves or creates a secure, private per-user directory for SecretGuard state (never falls back to shared /tmp)
pub fn get_vault_dir() -> Result<PathBuf, String> {
    if let Ok(dir_str) = env::var("SECRETGUARD_DIR") {
        let p = PathBuf::from(dir_str);
        fs::create_dir_all(&p).map_err(|e| format!("Failed to create SECRETGUARD_DIR at '{}': {}", p.display(), e))?;
        return Ok(p);
    }

    let base_dir = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .map_err(|_| "Environment Error: Neither HOME nor USERPROFILE is set. SecretGuard cannot securely locate the private user directory. Refusing to use a shared directory.".to_string())?;

    let dir = Path::new(&base_dir).join(".secretguard");
    fs::create_dir_all(&dir).map_err(|e| {
        format!("Failed to create secure user directory at '{}': {}", dir.display(), e)
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    Ok(dir)
}

pub fn get_vault_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_VAULT_PATH") {
        return Ok(PathBuf::from(p));
    }
    let dir = get_vault_dir()?;
    Ok(dir.join("vault.enc"))
}

pub fn get_master_key_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_MASTER_KEY_PATH") {
        return Ok(PathBuf::from(p));
    }
    let dir = get_vault_dir()?;
    Ok(dir.join(".master.key"))
}

/// Cross-platform atomic file replacement with Unix directory sync and Windows file replacement safety
pub fn atomic_replace_file(tmp_path: &Path, target_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Failed to atomically replace vault file {}: {}", target_path.display(), e)
        })?;

        // Issue 3: Propagate parent directory sync errors to guarantee journal commitment
        if let Some(parent) = target_path.parent() {
            let dir = fs::File::open(parent).map_err(|e| {
                format!("Failed to open parent directory '{}' for fsync: {}", parent.display(), e)
            })?;
            dir.sync_all().map_err(|e| {
                format!("Failed to fsync parent directory '{}' after vault replacement: {}", parent.display(), e)
            })?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // On modern Windows (Vista+), std::fs::rename within the same filesystem replaces existing destination atomically
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Windows atomic vault replacement failed for '{}': {}", target_path.display(), e)
        })
    }
}

/// Strips trailing CR (\r) and LF (\n) line terminators while preserving
/// leading and internal whitespace in secrets and passwords.
pub fn strip_line_terminator(s: &mut String) {
    if s.ends_with("\r\n") {
        s.truncate(s.len() - 2);
    } else if s.ends_with('\n') || s.ends_with('\r') {
        s.truncate(s.len() - 1);
    }
}

/// Retrieves or generates a genuine 256-bit cryptographically secure random master key via CSPRNG (OsRng)
/// with atomic, concurrency-safe 0600 file creation on Unix.
///
/// Returns Err if the master key path is a symlink (including dangling symlinks),
/// if permissions are insecure and cannot be tightened, or if the key length is corrupted.
pub fn get_or_generate_master_key() -> Result<[u8; 32], String> {
    let path = get_master_key_path()?;

    // Bounded retry loop (max 3 attempts) to eliminate recursion and prevent stack overflow
    for _attempt in 0..3 {
        // Inspect symlink metadata first to safely catch dangling symlinks without following them
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                // Issue 3: Explicitly reject symlinks (dangling or active)
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Security Error: Master key path '{}' is a symbolic link (or dangling symlink). Symbolic links are strictly prohibited for master keys to prevent hijacking.",
                        path.display()
                    ));
                }

                // Issue 2: Verify and enforce strict permissions on Unix (fail-closed if tightening fails)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    if mode & 0o077 != 0 {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                            format!(
                                "Security Error: Master key file '{}' permissions ({:o}) are insecure and could not be tightened to 0600: {}. Aborting for security.",
                                path.display(),
                                mode & 0o777,
                                e
                            )
                        })?;
                        // Re-verify after tightening
                        let re_meta = fs::symlink_metadata(&path).map_err(|e| {
                            format!("Failed to re-verify master key metadata after permission update: {}", e)
                        })?;
                        if re_meta.permissions().mode() & 0o077 != 0 {
                            return Err(format!(
                                "Security Error: Master key permissions on '{}' remain insecure ({:o}). Operation aborted.",
                                path.display(),
                                re_meta.permissions().mode() & 0o777
                            ));
                        }
                    }
                }

                let bytes = fs::read(&path).map_err(|e| {
                    format!(
                        "Permission denied or I/O error reading master key at '{}': {}. Aborting to protect vault integrity.",
                        path.display(),
                        e
                    )
                })?;

                if bytes.len() != 32 {
                    return Err(format!(
                        "Master key file at '{}' is corrupted (expected 32 bytes, found {} bytes). \
                         Aborting operation to prevent permanent vault data loss. Please restore your master key from backup.",
                        path.display(),
                        bytes.len()
                    ));
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // File does not exist: generate a new master key
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);

                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|err| {
                        format!(
                            "Failed to create master key directory '{}': {}",
                            parent.display(),
                            err
                        )
                    })?;
                }

                // Concurrency-safe exclusive creation
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    match fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(&path)
                    {
                        Ok(mut file) => {
                            if let Err(err) = file.write_all(&key).and_then(|_| file.sync_all()) {
                                let _ = fs::remove_file(&path);
                                return Err(format!(
                                    "Failed to persist master key to '{}': {}. Vault operations aborted.",
                                    path.display(),
                                    err
                                ));
                            }
                            return Ok(key);
                        }
                        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                            // Concurrent process created file; continue to next loop iteration to read & validate it
                            continue;
                        }
                        Err(err) => {
                            return Err(format!(
                                "Failed to create master key file '{}' with 0600 permissions: {}",
                                path.display(),
                                err
                            ));
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    use std::fs::OpenOptions;
                    match OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&path)
                    {
                        Ok(mut file) => {
                            if let Err(err) = file.write_all(&key).and_then(|_| file.sync_all()) {
                                let _ = fs::remove_file(&path);
                                return Err(format!(
                                    "Failed to persist master key to '{}': {}. Vault operations aborted.",
                                    path.display(),
                                    err
                                ));
                            }
                            return Ok(key);
                        }
                        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                            continue;
                        }
                        Err(err) => {
                            return Err(format!(
                                "Failed to create master key file '{}': {}",
                                path.display(),
                                err
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Filesystem error inspecting master key path '{}': {}",
                    path.display(),
                    e
                ));
            }
        }
    }

    Err(format!(
        "Failed to safely access or create master key at '{}' after multiple attempts.",
        path.display()
    ))
}

/// RFC 5869 HKDF-SHA256 (Extract and Expand) using official audited `hkdf` crate
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("Valid length for HKDF-SHA256 expansion");
    okm
}

pub fn derive_vault_key(passphrase: Option<&str>) -> Result<[u8; 32], String> {
    let master = get_or_generate_master_key()?;
    let salt = match passphrase {
        Some(pass) => pass.as_bytes(),
        None => b"secretguard_vault_rfc5869_salt_v3",
    };
    let info = b"SECRETGUARD_RFC5869_HKDF_AES256GCM_KEY";
    let derived = hkdf_sha256(salt, &master, info, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&derived[..32]);
    Ok(key)
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
    let path = get_vault_path()?;
    if !path.exists() {
        return Ok(VaultStore::default());
    }

    let data = fs::read(&path).map_err(|e| format!("Failed to read vault file at '{}': {}", path.display(), e))?;
    let key = derive_vault_key(passphrase)?;
    let decrypted = decrypt_vault_payload(&data, &key)?;
    let store: VaultStore = serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse decrypted vault data: {}", e))?;
    Ok(store)
}

pub fn save_vault(store: &VaultStore, passphrase: Option<&str>) -> Result<(), String> {
    let path = get_vault_path()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| format!("Failed to create vault directory '{}': {}", parent.display(), e))?;

    let json_bytes =
        serde_json::to_vec(store).map_err(|e| format!("Failed to serialize vault: {}", e))?;
    let key = derive_vault_key(passphrase)?;
    let encrypted = encrypt_vault_payload(&json_bytes, &key)?;

    // Unpredictable unique temporary file to eliminate race conditions and symlink replacement vulnerabilities
    let pid = process::id();
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let tmp_filename = format!(".vault.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
    let tmp_path = parent.join(tmp_filename);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create unique temporary vault file {} with 0600 mode: {}", tmp_path.display(), e))?;
        
        let write_res = file.write_all(&encrypted).and_then(|_| file.sync_all());
        if let Err(e) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to write and sync encrypted vault data to {}: {}", tmp_path.display(), e));
        }
    }
    #[cfg(not(unix))]
    {
        use std::fs::OpenOptions;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create unique temporary vault file {}: {}", tmp_path.display(), e))?;
        
        let write_res = file.write_all(&encrypted).and_then(|_| file.sync_all());
        if let Err(e) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to write and sync encrypted vault data to {}: {}", tmp_path.display(), e));
        }
    }

    atomic_replace_file(&tmp_path, &path)?;

    Ok(())
}

#[cfg(unix)]
struct SttyEchoGuard;

#[cfg(unix)]
impl Drop for SttyEchoGuard {
    fn drop(&mut self) {
        let _ = Command::new("stty").arg("echo").status();
    }
}

/// Reads a password or secret from the terminal with terminal echo disabled (zero external dependencies).
/// Fails closed if terminal echo cannot be disabled. On Unix, uses an RAII guard to guarantee echo is restored.
pub fn read_password_hidden(prompt: &str) -> io::Result<String> {
    #[cfg(unix)]
    {
        eprint!("{}", prompt);
        let _ = io::stderr().flush();

        // Disable echo and fail closed if stty fails
        let status = Command::new("stty")
            .arg("-echo")
            .status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to invoke stty to disable echo: {}", e)))?;

        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cannot disable terminal echo (stty returned non-zero). Failing closed to prevent secret leakage in terminal.",
            ));
        }

        // RAII guard guarantees stty echo is restored even on panic or error
        let _guard = SttyEchoGuard;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        eprintln!();
        strip_line_terminator(&mut input);
        Ok(input)
    }
    #[cfg(not(unix))]
    {
        eprint!("{}", prompt);
        let _ = io::stderr().flush();
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "$p = Read-Host -AsSecureString; if ($p) { [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p)) }",
            ])
            .output()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to invoke PowerShell for hidden input: {}", e)))?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PowerShell secure input failed. Failing closed to prevent secret leakage in terminal.",
            ));
        }

        let mut s = String::from_utf8(output.stdout)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8 from secure input: {}", e)))?;
        eprintln!();
        strip_line_terminator(&mut s);
        Ok(s)
    }
}

pub fn run_vault_cli(args: &[String], engine: &SecretGuardEngine) {
    if args.is_empty() {
        eprintln!(
            r#"SecretGuard Encrypted Zero-Knowledge Memory Vault (v0.3.6)

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
                eprintln!("\nSafe Usage:");
                eprintln!("  secretguard vault set <KEY_NAME>          (prompts interactively with hidden input, preventing shell & ps leaks)");
                eprintln!("  cat secret.txt | secretguard vault set <KEY_NAME>  (reads secret securely from piped stdin)");
                process::exit(2);
            }
            let key_name = &args[1];

            // Finding 1 & 3: Protect secrets from leaking through command-line arguments and terminal echo
            let secret_val = if args.len() >= 3 {
                eprintln!("⚠️  SECURITY WARNING: Passing secrets as CLI arguments exposes them in process listings ('ps aux')");
                eprintln!("   and shell history files. Prefer 'secretguard vault set {}' (interactive/stdin).\n", key_name);
                args[2].clone()
            } else {
                use std::io::IsTerminal;
                if io::stdin().is_terminal() {
                    // Disable terminal echo (fail-closed if echo cannot be disabled)
                    let prompt = format!("Enter secret value for '{}' (input hidden): ", key_name);
                    match read_password_hidden(&prompt) {
                        Ok(val) => val,
                        Err(e) => {
                            eprintln!("❌ Security failure reading hidden secret: {}", e);
                            eprintln!("🛑 Aborting: SecretGuard refuses to read secrets with terminal echo enabled.");
                            process::exit(1);
                        }
                    }
                } else {
                    // Piped stdin
                    let mut buffer = String::new();
                    if let Err(e) = io::stdin().read_line(&mut buffer) {
                        eprintln!("❌ Failed to read secret from stdin: {}", e);
                        process::exit(1);
                    }
                    strip_line_terminator(&mut buffer);
                    buffer
                }
            };

            if secret_val.is_empty() {
                eprintln!("❌ Secret value cannot be empty.");
                process::exit(1);
            }

            // Finding 4: Never overwrite or default on a corrupted vault! Fail loudly to prevent data loss.
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting operation to prevent overwriting or destroying existing vault data.");
                    process::exit(1);
                }
            };

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

            // Finding 4: Never overwrite corrupted vault
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting operation to prevent data loss.");
                    process::exit(1);
                }
            };

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

            // Asynchronously sanitize child stderr using chunk/delimiter streaming while preserving binary fidelity
            let stderr_opt = child.stderr.take();
            let stderr_thread = std::thread::spawn(move || {
                if let Some(stderr) = stderr_opt {
                    let mut reader = io::BufReader::new(stderr);
                    let stderr_handle = io::stderr();
                    let mut handle = stderr_handle.lock();
                    let local_engine = SecretGuardEngine::new();
                    let mut buf = Vec::new();
                    while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                        if n == 0 {
                            break;
                        }
                        match std::str::from_utf8(&buf) {
                            Ok(text_chunk) => {
                                let res = local_engine.scan_and_sanitize(text_chunk);
                                let _ = handle.write_all(res.sanitized_text.as_bytes());
                            }
                            Err(_) => {
                                // Raw binary chunk: preserve byte-for-byte without lossy UTF-8 conversion
                                let _ = handle.write_all(&buf);
                            }
                        }
                        let _ = handle.flush();
                        buf.clear();
                    }
                }
            });

            if let Some(stdout) = child.stdout.take() {
                let mut reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();
                let mut buf = Vec::new();
                while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                    if n == 0 {
                        break;
                    }
                    match std::str::from_utf8(&buf) {
                        Ok(text_chunk) => {
                            let res = engine.scan_and_sanitize(text_chunk);
                            let _ = handle.write_all(res.sanitized_text.as_bytes());
                        }
                        Err(_) => {
                            // Raw binary chunk: preserve byte-for-byte without lossy UTF-8 conversion
                            let _ = handle.write_all(&buf);
                        }
                    }
                    let _ = handle.flush();
                    buf.clear();
                }
            }

            let _ = stderr_thread.join();
            let status = child.wait().expect("Child process was not running");

            // Finding 8: Accurate process exit status handling for Unix signals and Windows errors
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(code) = status.code() {
                    process::exit(code);
                } else if let Some(sig) = status.signal() {
                    process::exit(128 + sig);
                } else {
                    process::exit(1);
                }
            }
            #[cfg(not(unix))]
            {
                process::exit(status.code().unwrap_or(1));
            }
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

            // Finding 4: Never overwrite or default on a corrupted vault
            let mut store = match load_vault(None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("❌ FATAL: Cannot open vault: {}", e);
                    eprintln!("🛑 Aborting import to protect existing vault contents.");
                    process::exit(1);
                }
            };

            let mut imported = 0;
            let mut example_lines = Vec::new();

            // Finding 9: Robust .env parser handling export, quotes, inline comments, and syntax
            for line in reader.lines().flatten() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    example_lines.push(line);
                    continue;
                }

                // Strip leading 'export ' if present (common in bash env scripts)
                let clean_line = if trimmed.starts_with("export ") {
                    trimmed.strip_prefix("export ").unwrap_or(trimmed).trim()
                } else {
                    trimmed
                };

                if let Some((k, mut v)) = clean_line.split_once('=') {
                    let key = k.trim().to_string();

                    // Validate key identifier format
                    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || key.is_empty() {
                        example_lines.push(line);
                        continue;
                    }

                    v = v.trim();

                    // Strip inline comment only if outside of quotes
                    let val = if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
                        || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
                    {
                        v[1..v.len() - 1].to_string()
                    } else if let Some((before_comment, _)) = v.split_once(" #") {
                        before_comment.trim().trim_matches('"').trim_matches('\'').to_string()
                    } else {
                        v.trim_matches('"').trim_matches('\'').to_string()
                    };

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
