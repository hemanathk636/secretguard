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

#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[cfg(unix)]
static TERMINAL_INTERRUPTED: AtomicBool = AtomicBool::new(false);
#[cfg(unix)]
static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" {
    fn getuid() -> u32;
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn siginterrupt(signum: i32, flag: i32) -> i32;
}

#[cfg(unix)]
extern "C" fn sig_flag_handler(sig: i32) {
    TERMINAL_INTERRUPTED.store(true, Ordering::SeqCst);
    RECEIVED_SIGNAL.store(sig, Ordering::SeqCst);
}

#[cfg(windows)]
mod win32 {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    #[allow(dead_code)]
    pub const REPLACEFILE_WRITE_THROUGH: u32 = 0x00000001;
    #[allow(dead_code)]
    pub const REPLACEFILE_IGNORE_MERGE_ERRORS: u32 = 0x00000002;
    #[allow(dead_code)]
    pub const REPLACEFILE_IGNORE_ACL_ERRORS: u32 = 0x00000004;

    extern "system" {
        pub fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut std::ffi::c_void,
            lpReserved: *mut std::ffi::c_void,
        ) -> i32;

        pub fn GetLastError() -> u32;
    }

    pub fn to_wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

/// Validates that `path` and its parent directory meet strict security guarantees on Unix:
/// 1. Parent directory must exist, must not be a symlink, and must be owned by active user or root.
/// 2. Parent directory must not be group-writable or world-writable unless it is a root-owned sticky directory (e.g. /tmp with 0o1777).
/// 3. The target itself must not be a symlink and must be owned by active user.
/// 4. Private permissions are strictly enforced (0o700 for directories, 0o600 for files) and re-verified.
/// Fails closed upon any filesystem metadata inspection error.
pub fn validate_secure_path(path: &Path, is_file: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let active_uid = unsafe { getuid() };

        // 1. Parent directory validation
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let p_meta = fs::symlink_metadata(parent).map_err(|e| {
                    format!("Security Error: Failed to inspect metadata on parent directory '{}': {}. Aborting.", parent.display(), e)
                })?;

                if p_meta.file_type().is_symlink() {
                    return Err(format!("Security Error: Parent directory '{}' is a symbolic link. Aborting.", parent.display()));
                }

                if p_meta.uid() != active_uid && p_meta.uid() != 0 {
                    return Err(format!(
                        "Security Error: Parent directory '{}' is owned by UID {} (expected active user UID {} or root). Aborting.",
                        parent.display(),
                        p_meta.uid(),
                        active_uid
                    ));
                }

                let mode = p_meta.permissions().mode();
                if p_meta.uid() == 0 {
                    let is_sticky = (mode & 0o1000) != 0;
                    if !is_sticky && (mode & 0o022) != 0 {
                        return Err(format!(
                            "Security Error: Root-owned parent directory '{}' is writable by group/others ({:o}) without sticky bit. Aborting.",
                            parent.display(),
                            mode & 0o777
                        ));
                    }
                } else {
                    if (mode & 0o022) != 0 {
                        return Err(format!(
                            "Security Error: Parent directory '{}' has insecure permissions ({:o}, group/world-writable). Aborting.",
                            parent.display(),
                            mode & 0o777
                        ));
                    }
                }
            }
        }

        // 2. Target path validation (if already existing)
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Security Error: Target path '{}' is a symbolic link. Symbolic links are strictly prohibited for vault storage.",
                    path.display()
                ));
            }

            if meta.uid() != active_uid {
                return Err(format!(
                    "Security Error: Target path '{}' is owned by UID {} but active user is UID {}. Aborting.",
                    path.display(),
                    meta.uid(),
                    active_uid
                ));
            }

            let target_mode = if is_file { 0o600 } else { 0o700 };
            fs::set_permissions(path, fs::Permissions::from_mode(target_mode)).map_err(|e| {
                format!("Security Error: Failed to enforce {:o} permissions on '{}': {}. Aborting.", target_mode, path.display(), e)
            })?;

            let re_meta = fs::symlink_metadata(path).map_err(|e| {
                format!("Security Error: Failed to re-verify permissions on '{}': {}. Aborting.", path.display(), e)
            })?;

            if re_meta.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "Security Error: Target path '{}' permissions are insecure ({:o}). Operation aborted.",
                    path.display(),
                    re_meta.permissions().mode() & 0o777
                ));
            }
        }
    }
    let _ = (path, is_file);
    Ok(())
}

/// Resolves or creates a secure, private per-user directory for SecretGuard state (never falls back to shared /tmp).
/// Fails closed if 0700 private directory permissions, non-symlink status, parent ownership, or user ownership cannot be established on Unix.
pub fn get_vault_dir() -> Result<PathBuf, String> {
    if let Ok(dir_str) = env::var("SECRETGUARD_DIR") {
        let p = PathBuf::from(dir_str);
        fs::create_dir_all(&p).map_err(|e| format!("Failed to create SECRETGUARD_DIR at '{}': {}", p.display(), e))?;
        validate_secure_path(&p, false)?;
        return Ok(p);
    }

    let base_dir = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .map_err(|_| "Environment Error: Neither HOME nor USERPROFILE is set. SecretGuard cannot securely locate the private user directory. Refusing to use a shared directory.".to_string())?;

    let dir = Path::new(&base_dir).join(".secretguard");
    fs::create_dir_all(&dir).map_err(|e| {
        format!("Failed to create secure user directory at '{}': {}", dir.display(), e)
    })?;
    validate_secure_path(&dir, false)?;
    Ok(dir)
}

pub fn get_vault_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_VAULT_PATH") {
        let path = PathBuf::from(p);
        validate_secure_path(&path, true)?;
        return Ok(path);
    }
    let dir = get_vault_dir()?;
    let path = dir.join("vault.enc");
    validate_secure_path(&path, true)?;
    Ok(path)
}

pub fn get_master_key_path() -> Result<PathBuf, String> {
    if let Ok(p) = env::var("SECRETGUARD_MASTER_KEY_PATH") {
        let path = PathBuf::from(p);
        validate_secure_path(&path, true)?;
        return Ok(path);
    }
    let dir = get_vault_dir()?;
    let path = dir.join(".master.key");
    validate_secure_path(&path, true)?;
    Ok(path)
}

/// Cross-platform atomic file replacement:
/// - On Unix: atomic rename followed by explicit parent directory fsync to guarantee metadata journal commit.
/// - On Windows: race-free bounded retry loop (5 attempts) distinguishing first-time creation from in-place ReplaceFileW.
pub fn atomic_replace_file(tmp_path: &Path, target_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Failed to atomically replace vault file {}: {}", target_path.display(), e)
        })?;

        // Propagate parent directory sync errors to guarantee journal commitment
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
    #[cfg(windows)]
    {
        // Bounded retry loop (5 attempts) eliminating any TOCTOU race between target existing or being concurrently created
        for attempt in 0..5 {
            if target_path.exists() {
                let replaced_w = win32::to_wide_null(target_path);
                let replacement_w = win32::to_wide_null(tmp_path);

                let flags = win32::REPLACEFILE_WRITE_THROUGH | win32::REPLACEFILE_IGNORE_MERGE_ERRORS;
                let success = unsafe {
                    win32::ReplaceFileW(
                        replaced_w.as_ptr(),
                        replacement_w.as_ptr(),
                        std::ptr::null(), // atomic in-place swap without backup file
                        flags,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if success != 0 {
                    return Ok(());
                }

                let err = unsafe { win32::GetLastError() };
                // ERROR_FILE_NOT_FOUND (2): target was removed in that microsecond; retry as initial rename
                if err == 2 && attempt < 4 {
                    std::thread::yield_now();
                    continue;
                }

                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(5 * (attempt + 1) as u64));
                    continue;
                }

                let _ = fs::remove_file(tmp_path);
                return Err(format!(
                    "Windows ReplaceFileW failed to atomically replace '{}' with temporary vault '{}' (Win32 error: {}).",
                    target_path.display(),
                    tmp_path.display(),
                    err
                ));
            } else {
                // Target does not exist yet (first-time vault creation)
                match fs::rename(tmp_path, target_path) {
                    Ok(()) => return Ok(()),
                    Err(e) if (e.kind() == io::ErrorKind::AlreadyExists || e.kind() == io::ErrorKind::PermissionDenied) && attempt < 4 => {
                        // Concurrent process created target in this window; loop to ReplaceFileW
                        std::thread::yield_now();
                        continue;
                    }
                    Err(e) => {
                        if attempt < 4 {
                            std::thread::sleep(std::time::Duration::from_millis(5 * (attempt + 1) as u64));
                            continue;
                        }
                        let _ = fs::remove_file(tmp_path);
                        return Err(format!("Windows initial vault creation failed for '{}': {}", target_path.display(), e));
                    }
                }
            }
        }
        let _ = fs::remove_file(tmp_path);
        Err(format!("Windows atomic vault replacement failed after 5 retry attempts for '{}'", target_path.display()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::rename(tmp_path, target_path).map_err(|e| {
            let _ = fs::remove_file(tmp_path);
            format!("Failed to rename {} to {}: {}", tmp_path.display(), target_path.display(), e)
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
/// Fails closed if terminal echo cannot be disabled. On Unix, terminal echo is restored both explicitly,
/// via an RAII drop guard for stack unwinding, and via catchable signal handlers (SIGINT / SIGTERM).
///
/// Note on termination: Uncatchable OS-level signals (such as SIGKILL/SIGSTOP) or release panic=abort
/// cannot execute userspace unwinding destructors. In such unexpected crash conditions, users can reset
/// their terminal with the standard `reset` or `stty sane` command.
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

        // Reset signal flags before input
        TERMINAL_INTERRUPTED.store(false, Ordering::SeqCst);
        RECEIVED_SIGNAL.store(0, Ordering::SeqCst);

        // Install async-signal-safe flag handlers for SIGINT (Ctrl+C) and SIGTERM
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        let old_sigint = unsafe { signal(SIGINT, sig_flag_handler) };
        let old_sigterm = unsafe { signal(SIGTERM, sig_flag_handler) };
        unsafe {
            siginterrupt(SIGINT, 1);
            siginterrupt(SIGTERM, 1);
        }

        // RAII guard guarantees stty echo is restored even on panic or error
        let _guard = SttyEchoGuard;

        let mut input = String::new();
        let res = io::stdin().read_line(&mut input);

        // Explicitly restore echo in normal userspace context (guaranteed async-signal-safe architecture)
        let _ = Command::new("stty").arg("echo").status();

        // Restore previous signal handlers
        unsafe {
            signal(SIGINT, std::mem::transmute(old_sigint));
            signal(SIGTERM, std::mem::transmute(old_sigterm));
        }

        if TERMINAL_INTERRUPTED.load(Ordering::SeqCst) {
            let sig = RECEIVED_SIGNAL.load(Ordering::SeqCst);
            let exit_code = if sig == SIGTERM {
                143 // 128 + 15
            } else if sig == SIGINT {
                130 // 128 + 2
            } else {
                128 + sig
            };
            eprintln!();
            std::process::exit(exit_code);
        }

        eprintln!();
        res?;
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

/// Replaces occurrences of `needle` in `haystack` at the raw byte level,
/// without modifying any surrounding non-UTF-8 or binary bytes.
pub fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut result = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i <= haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            result.extend_from_slice(replacement);
            i += needle.len();
        } else {
            result.push(haystack[i]);
            i += 1;
        }
    }
    if i < haystack.len() {
        result.extend_from_slice(&haystack[i..]);
    }
    result
}

/// Stream sanitizer that maintains a bounded tail holdback buffer (4096 bytes) to guarantee that:
/// 1. Long credentials (up to 4KB, covering 4096-bit RSA private key PEM headers/blocks, extended JWTs,
///    and AWS temporary session tokens) are detected even when split across arbitrary chunk boundaries.
/// 2. Partial credentials are NEVER emitted prematurely before succeeding chunks arrive.
/// 3. Clean binary streams are preserved byte-for-byte.
/// 4. Binary streams containing embedded credentials preserve all surrounding non-secret invalid UTF-8 bytes.
pub struct StreamSanitizer {
    buffer: Vec<u8>,
}

impl StreamSanitizer {
    /// Maximum supported credential length across stream boundaries (4096 bytes / 4 KB).
    pub const WINDOW_SIZE: usize = 4096;

    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// Internal helper to sanitize a slice of bytes while preserving binary fidelity.
    pub fn sanitize_bytes_internal(bytes: &[u8], engine: &SecretGuardEngine) -> (Vec<u8>, bool) {
        let lossy = String::from_utf8_lossy(bytes);
        let res = engine.scan_and_sanitize(&lossy);

        if !res.has_secret {
            return (bytes.to_vec(), false);
        }

        // If the original buffer is valid UTF-8, emit the standard sanitized text
        if std::str::from_utf8(bytes).is_ok() {
            return (res.sanitized_text.into_bytes(), true);
        }

        // Buffer contains binary / invalid UTF-8 bytes:
        // Perform surgical byte-level replacement for each detected secret,
        // preserving all surrounding invalid UTF-8 bytes byte-for-byte!
        let mut sanitized = bytes.to_vec();
        for (secret, replacement) in &res.redacted_pairs {
            sanitized = replace_bytes(&sanitized, secret.as_bytes(), replacement.as_bytes());
        }
        (sanitized, true)
    }

    pub fn sanitize_chunk(&mut self, chunk: &[u8], engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
        self.buffer.extend_from_slice(chunk);

        // If buffer is larger than WINDOW_SIZE, process and emit the prefix
        // while holding back the tail WINDOW_SIZE bytes to prevent premature partial emission
        if self.buffer.len() > Self::WINDOW_SIZE {
            let safe_drain_point = self.buffer.len() - Self::WINDOW_SIZE;

            let (sanitized_bytes, has_secret) = Self::sanitize_bytes_internal(&self.buffer, engine);

            if has_secret {
                if sanitized_bytes.len() > Self::WINDOW_SIZE {
                    let drain = sanitized_bytes.len() - Self::WINDOW_SIZE;
                    out.write_all(&sanitized_bytes[..drain])?;
                    self.buffer = sanitized_bytes[drain..].to_vec();
                } else {
                    self.buffer = sanitized_bytes;
                }
            } else {
                // No secret detected: safely write out prefix
                out.write_all(&self.buffer[..safe_drain_point])?;
                self.buffer = self.buffer[safe_drain_point..].to_vec();
            }
        }

        out.flush()
    }

    pub fn flush_final(&mut self, engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let (sanitized_bytes, _) = Self::sanitize_bytes_internal(&self.buffer, engine);
            out.write_all(&sanitized_bytes)?;
            self.buffer.clear();
            out.flush()?;
        }
        Ok(())
    }
}

/// Sanitizes a stream buffer while preserving binary stream fidelity and guaranteeing
/// that credentials embedded inside binary chunks cannot escape redaction.
pub fn sanitize_stream_buffer(buf: &[u8], engine: &SecretGuardEngine, out: &mut impl Write) -> io::Result<()> {
    let mut sanitizer = StreamSanitizer::new();
    sanitizer.sanitize_chunk(buf, engine, out)?;
    sanitizer.flush_final(engine, out)
}

pub fn run_vault_cli(args: &[String], engine: &SecretGuardEngine) {
    if args.is_empty() {
        eprintln!(
            r#"SecretGuard Encrypted Zero-Knowledge Memory Vault (v0.3.10)

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

            // Asynchronously sanitize child stderr using chunk/delimiter streaming with bounded overlap window
            // guaranteeing that credentials split across chunk boundaries are detected and redacted
            let stderr_opt = child.stderr.take();
            let stderr_thread = std::thread::spawn(move || {
                if let Some(stderr) = stderr_opt {
                    let mut reader = io::BufReader::new(stderr);
                    let stderr_handle = io::stderr();
                    let mut handle = stderr_handle.lock();
                    let local_engine = SecretGuardEngine::new();
                    let mut sanitizer = StreamSanitizer::new();
                    let mut buf = Vec::new();
                    while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                        if n == 0 {
                            break;
                        }
                        let _ = sanitizer.sanitize_chunk(&buf, &local_engine, &mut handle);
                        buf.clear();
                    }
                    let _ = sanitizer.flush_final(&local_engine, &mut handle);
                }
            });

            if let Some(stdout) = child.stdout.take() {
                let mut reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();
                let mut sanitizer = StreamSanitizer::new();
                let mut buf = Vec::new();
                while let Ok(n) = reader.read_until(b'\n', &mut buf) {
                    if n == 0 {
                        break;
                    }
                    let _ = sanitizer.sanitize_chunk(&buf, engine, &mut handle);
                    buf.clear();
                }
                let _ = sanitizer.flush_final(engine, &mut handle);
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
