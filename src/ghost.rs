use crate::vault::{
    decrypt_vault_payload, derive_vault_key, encrypt_vault_payload, volatile_zeroize,
    volatile_zeroize_str,
};
use crate::SecretGuardEngine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GhostSessionTable {
    pub mappings: HashMap<String, String>, // ghost_token -> real_token
}

impl Drop for GhostSessionTable {
    fn drop(&mut self) {
        for (_, mut real_val) in self.mappings.drain() {
            volatile_zeroize_str(&mut real_val);
        }
    }
}

const STALE_LOCK_AGE_SECS: u64 = 30;

fn in_process_ghost_mutex() -> &'static Mutex<()> {
    static MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    MUTEX.get_or_init(|| Mutex::new(()))
}

#[cfg(unix)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if res == 0 {
        return true;
    }
    matches!(std::io::Error::last_os_error().raw_os_error(), Some(e) if e == libc::EPERM)
}

#[cfg(windows)]
pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    extern "system" {
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // ERROR_ACCESS_DENIED (5) means process exists; ERROR_INVALID_PARAMETER (87) means dead
        return std::io::Error::last_os_error().raw_os_error() == Some(5);
    }
    let mut exit_code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe { CloseHandle(handle) };
    ok != 0 && exit_code == STILL_ACTIVE
}

#[cfg(not(any(unix, windows)))]
pub fn is_pid_alive(_pid: u32) -> bool {
    true
}

struct GhostLockGuard {
    _proc_guard: MutexGuard<'static, ()>,
    lock_path: PathBuf,
    owner_tag: String,
}

impl GhostLockGuard {
    fn is_lock_stale(lock_path: &Path) -> Result<bool, String> {
        let meta = match fs::symlink_metadata(lock_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(format!(
                    "Security Error: Failed to inspect Ghost lockfile '{}': {}",
                    lock_path.display(),
                    e
                ))
            }
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Security Error: Ghost lockfile '{}' is a symlink/reparse point. Aborting.",
                lock_path.display()
            ));
        }

        if let Ok(content) = fs::read_to_string(lock_path) {
            if let Some(pid_line) = content.lines().find(|l| l.starts_with("pid=")) {
                if let Ok(pid) = pid_line.trim_start_matches("pid=").trim().parse::<u32>() {
                    // If owning PID is still alive, lock is NEVER stale regardless of age
                    if is_pid_alive(pid) {
                        return Ok(false);
                    }
                    // Owning PID is dead -> lock is stale and safe to reclaim
                    return Ok(true);
                }
            }
        }

        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                if elapsed.as_secs() >= STALE_LOCK_AGE_SECS {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn acquire(session_path: &Path) -> Result<Self, String> {
        let proc_guard = in_process_ghost_mutex()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let parent = session_path.parent().unwrap_or_else(|| Path::new("."));
        let lock_path = parent.join(".ghost_session.lock");
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let owner_tag = format!(
            "pid={}\nnonce={:016x}\n",
            std::process::id(),
            u64::from_le_bytes(nonce)
        );

        for attempt in 0..50 {
            if Self::is_lock_stale(&lock_path)? {
                // Atomic rename ensures only ONE racing reclaimer removes the stale lockfile
                let mut r_nonce = [0u8; 8];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut r_nonce);
                let reclaim_tmp = parent.join(format!(
                    ".ghost_session.stale.{}.{:x}",
                    std::process::id(),
                    u64::from_le_bytes(r_nonce)
                ));
                if fs::rename(&lock_path, &reclaim_tmp).is_ok() {
                    let _ = fs::remove_file(&reclaim_tmp);
                }
            }
            match crate::vault::create_secure_file_exclusive(&lock_path, 0o600) {
                Ok(mut f) => {
                    let _ = f.write_all(owner_tag.as_bytes());
                    let _ = f.sync_all();
                    return Ok(Self {
                        _proc_guard: proc_guard,
                        lock_path,
                        owner_tag,
                    });
                }
                Err(err) => {
                    if err.contains("symlink")
                        || err.contains("reparse")
                        || err.contains("Insecure permissions")
                    {
                        return Err(err);
                    }
                    if attempt == 49 {
                        return Err(format!(
                            "Security Error: Timed out acquiring Ghost session lock at '{}': {}",
                            lock_path.display(),
                            err
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        Err(format!(
            "Security Error: Timed out acquiring Ghost session lock at '{}'.",
            lock_path.display()
        ))
    }
}

impl Drop for GhostLockGuard {
    fn drop(&mut self) {
        if let Ok(content) = fs::read_to_string(&self.lock_path) {
            if content == self.owner_tag {
                let _ = fs::remove_file(&self.lock_path);
            }
        }
    }
}

pub struct GhostVirtualizer;

impl GhostVirtualizer {
    pub fn try_get_session_path() -> Result<PathBuf, String> {
        if let Ok(p) = std::env::var("SECRETGUARD_GHOST_PATH") {
            let path = PathBuf::from(p);
            crate::vault::validate_secure_path(&path, true)?;
            return Ok(path);
        }
        let base_dir = std::env::var("SECRETGUARD_DIR")
            .or_else(|_| std::env::var("USERPROFILE"))
            .or_else(|_| std::env::var("HOME"))
            .map_err(|_| {
                "Security Error: Neither SECRETGUARD_DIR, USERPROFILE, nor HOME environment variable is set. Shared /tmp fallback is disabled to prevent multi-user symlink and interception vulnerabilities.".to_string()
            })?;
        let dir = Path::new(&base_dir).join(".secretguard");
        crate::vault::validate_secure_path(&dir, false)?;
        fs::create_dir_all(&dir).map_err(|e| {
            format!(
                "Failed to create .secretguard directory '{}': {}",
                dir.display(),
                e
            )
        })?;
        let session_file = dir.join("ghost_session.enc");
        crate::vault::validate_secure_path(&session_file, true)?;
        Ok(session_file)
    }

    pub fn get_session_path() -> PathBuf {
        Self::try_get_session_path().unwrap_or_else(|e| panic!("{}", e))
    }

    fn get_encryption_key() -> Result<[u8; 32], String> {
        derive_vault_key(Some("secretguard_ghost_virtualizer_entropy_key"))
    }

    /// Loads encrypted Ghost token mapping from disk (AES-256-GCM).
    /// Returns Ok(Default) only if session file does not exist.
    /// Returns Err if the session file exists but is corrupted, unreadable, or fails decryption (fail closed).
    pub fn try_load_session() -> Result<GhostSessionTable, String> {
        let path = Self::try_get_session_path()?;
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GhostSessionTable::default());
            }
            Err(e) => {
                return Err(format!(
                    "Failed to inspect Ghost session file metadata: {}",
                    e
                ));
            }
        };

        if meta.file_type().is_symlink() {
            return Err("Security Error: Ghost session file is an untrusted symlink!".to_string());
        }

        let encrypted_bytes =
            fs::read(&path).map_err(|e| format!("Failed to read Ghost session file: {}", e))?;
        let mut key = Self::get_encryption_key()?;
        let decrypt_res = decrypt_vault_payload(&encrypted_bytes, &key);
        volatile_zeroize(&mut key);

        let mut decrypted_bytes = decrypt_res
            .map_err(|e| format!("Security Error: Ghost session decryption failed: {}", e))?;
        let parsed = serde_json::from_slice::<GhostSessionTable>(&decrypted_bytes)
            .map_err(|e| format!("Invalid Ghost session table format: {}", e));
        volatile_zeroize(&mut decrypted_bytes);
        parsed
    }

    /// Backwards-compatible load_session that falls back with warning
    pub fn load_session() -> GhostSessionTable {
        Self::try_load_session().unwrap_or_else(|e| {
            eprintln!("⚠️ Warning: {}", e);
            GhostSessionTable::default()
        })
    }

    /// Encrypts and securely persists Ghost token mapping atomically with restricted permissions,
    /// exclusive file creation semantics, symlink rejection, parent fsync, and atomic replacement.
    pub fn save_session(table: &GhostSessionTable) -> Result<(), std::io::Error> {
        let path = Self::try_get_session_path()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _ = fs::create_dir_all(parent);

        // Clean up legacy plaintext session file if it exists (rejecting symlinks)
        let legacy_json = path.with_extension("json");
        if let Ok(m) = fs::symlink_metadata(&legacy_json) {
            if !m.file_type().is_symlink() {
                let _ = fs::remove_file(&legacy_json);
            }
        }

        let mut serialized = serde_json::to_vec(table)?;
        let mut key = Self::get_encryption_key().map_err(|e| {
            volatile_zeroize(&mut serialized);
            std::io::Error::other(e)
        })?;
        let encrypted_res = encrypt_vault_payload(&serialized, &key);
        volatile_zeroize(&mut serialized);
        volatile_zeroize(&mut key);
        let encrypted = encrypted_res.map_err(std::io::Error::other)?;

        // Unpredictable unique temporary file to eliminate race conditions and symlink replacement vulnerabilities
        let pid = std::process::id();
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let tmp_filename = format!(".ghost_session.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
        let temp_path = parent.join(tmp_filename);

        let mut file = crate::vault::create_secure_file_exclusive(&temp_path, 0o600)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let write_res = file.write_all(&encrypted).and_then(|_| file.sync_all());
        if let Err(e) = write_res {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }
        drop(file);

        crate::vault::atomic_replace_file(&temp_path, &path).map_err(std::io::Error::other)?;

        Ok(())
    }

    fn get_token_hmac_key() -> [u8; 32] {
        static EPHEMERAL_FALLBACK: OnceLock<[u8; 32]> = OnceLock::new();
        if let Ok(key) = derive_vault_key(Some("secretguard_ghost_token_hmac_v2")) {
            return key;
        }
        *EPHEMERAL_FALLBACK.get_or_init(|| {
            let mut k = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut k);
            k
        })
    }

    /// Generates a format-preserving polymorphic Ghost Token using keyed HMAC-SHA256
    /// (preventing offline dictionary/brute-force attacks against low-entropy secrets).
    pub fn create_ghost_token(real_key: &str) -> String {
        let mut hmac_key = Self::get_token_hmac_key();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(b"SECRETGUARD_GHOST_HMAC_v2");
        mac.update(real_key.as_bytes());
        let mut digest = mac.finalize().into_bytes();
        volatile_zeroize(&mut hmac_key);

        let hash: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        volatile_zeroize(digest.as_mut_slice());

        if real_key.starts_with("sk-proj-") || real_key.starts_with("sk-") {
            format!("sk-ghost-{}", &hash[0..36])
        } else if real_key.starts_with("AKIA") || real_key.starts_with("ASIA") {
            format!("AKIA_GHOST_{}", hash[0..12].to_uppercase())
        } else if real_key.starts_with("ghp_") || real_key.starts_with("gho_") {
            format!("ghp_ghost_{}", &hash[0..32])
        } else if real_key.starts_with("sk_live_") || real_key.starts_with("sk_test_") {
            format!("sk_ghost_{}", &hash[0..28])
        } else if real_key.starts_with("npm_") {
            format!("npm_ghost_{}", &hash[0..32])
        } else if real_key.starts_with("re_") {
            format!("re_ghost_{}", &hash[0..30])
        } else if real_key.starts_with("hf_") {
            format!("hf_ghost_{}", &hash[0..30])
        } else if real_key.starts_with("AIza") {
            format!("AIza_GHOST_{}", &hash[0..28])
        } else if real_key.starts_with("shpat_") {
            format!("shpat_ghost_{}", &hash[0..26])
        } else if real_key.starts_with("sntrys_") {
            format!("sntrys_ghost_{}", &hash[0..32])
        } else if real_key.starts_with("SG.") {
            format!("SG.ghost_{}", &hash[0..32])
        } else if real_key.starts_with("PMAK-") {
            format!("PMAK-ghost-{}", &hash[0..24])
        } else if real_key.starts_with("lin_api_") {
            format!("lin_ghost_{}", &hash[0..32])
        } else {
            format!("ghost_sec_{}", &hash[0..24])
        }
    }

    /// Virtualizes text, replacing real keys with Ghost Tokens and saving the encrypted mapping.
    /// When `fresh_session` is true, starts from an empty session table instead of merging with prior mappings.
    /// Fails closed if session persistence or locking fails.
    pub fn try_virtualize_text_with_options(
        input: &str,
        engine: &SecretGuardEngine,
        fresh_session: bool,
    ) -> Result<(String, usize), String> {
        let mut unique_secrets: Vec<String> = Vec::new();
        let mut seen = HashSet::new();

        for line in input.lines() {
            let mut scan = engine.scan_and_sanitize(line);
            if !scan.has_secret {
                continue;
            }
            for (mut real_secret, _) in scan.redacted_pairs.drain(..) {
                if !real_secret.is_empty() && seen.insert(real_secret.clone()) {
                    unique_secrets.push(real_secret);
                } else {
                    volatile_zeroize_str(&mut real_secret);
                }
            }
        }

        if unique_secrets.is_empty() {
            return Ok((input.to_string(), 0));
        }

        // Replace longest secrets first so shorter matches don't corrupt longer secrets
        unique_secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));

        let session_path = Self::try_get_session_path()?;
        let _lock = GhostLockGuard::acquire(&session_path)?;

        let mut session = if fresh_session {
            GhostSessionTable::default()
        } else {
            Self::try_load_session().map_err(|e| {
                format!(
                    "Security Error: Failed to load Ghost session (failing closed): {}",
                    e
                )
            })?
        };

        let mut output = input.to_string();
        let mut count = 0;

        for mut real_secret in unique_secrets {
            if output.contains(&real_secret) {
                // Preserve any existing mapping (including legacy v1 tokens) for this real secret
                let existing_ghost = session
                    .mappings
                    .iter()
                    .find(|(_, v)| *v == &real_secret)
                    .map(|(k, _)| k.clone());
                let mut ghost =
                    existing_ghost.unwrap_or_else(|| Self::create_ghost_token(&real_secret));
                let mut suffix_idx = 1usize;
                while let Some(mapped) = session.mappings.get(&ghost) {
                    if mapped == &real_secret {
                        break;
                    }
                    ghost = format!("{}_{}", Self::create_ghost_token(&real_secret), suffix_idx);
                    suffix_idx += 1;
                }
                output = output.replace(&real_secret, &ghost);
                session.mappings.insert(ghost, real_secret.clone());
                count += 1;
            }
            volatile_zeroize_str(&mut real_secret);
        }

        if count > 0 || fresh_session {
            Self::save_session(&session).map_err(|e| {
                format!(
                    "Security Error: Failed to securely persist Ghost session (failing closed): {}",
                    e
                )
            })?;
        }

        Ok((output, count))
    }

    /// Virtualizes text, replacing real keys with Ghost Tokens and saving the encrypted mapping.
    /// Fails closed if session persistence fails.
    pub fn try_virtualize_text(
        input: &str,
        engine: &SecretGuardEngine,
    ) -> Result<(String, usize), String> {
        Self::try_virtualize_text_with_options(input, engine, false)
    }

    /// Virtualizes text, failing closed with a panic if session persistence fails.
    pub fn virtualize_text(input: &str, engine: &SecretGuardEngine) -> (String, usize) {
        Self::try_virtualize_text(input, engine).unwrap_or_else(|e| panic!("{}", e))
    }

    pub fn virtualize_file_with_options(
        target_file: &Path,
        engine: &SecretGuardEngine,
        fresh_session: bool,
    ) -> Result<PathBuf, String> {
        use std::io::IsTerminal;
        crate::broker::SecurityBroker::authorize_local_secret_access(
            crate::policy::OperationType::DelegatedProcessExec,
            "GHOST_SESSION",
            &target_file.display().to_string(),
            std::io::stdin().is_terminal(),
        )?;

        let meta = fs::symlink_metadata(target_file).map_err(|e| {
            format!(
                "Target file '{}' could not be accessed: {}",
                target_file.display(),
                e
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Security Error: Target file '{}' is a symlink. Symlinks are rejected.",
                target_file.display()
            ));
        }

        let mut content =
            fs::read_to_string(target_file).map_err(|e| format!("Failed to read file: {}", e))?;

        let (virtualized, count) =
            Self::try_virtualize_text_with_options(&content, engine, fresh_session)?;
        volatile_zeroize_str(&mut content);
        let out_path = target_file.with_extension("ghost");

        // Verify out_path is not an existing untrusted symlink
        if let Ok(out_meta) = fs::symlink_metadata(&out_path) {
            if out_meta.file_type().is_symlink() {
                return Err(format!(
                    "Security Error: Destination path '{}' is a symlink. Symlink overwrite prohibited.",
                    out_path.display()
                ));
            }
        }

        let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
        let pid = std::process::id();
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let tmp_filename = format!(".ghost_out.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
        let temp_path = parent.join(tmp_filename);

        let mut file = crate::vault::create_secure_file_exclusive(&temp_path, 0o600)?;
        let write_res = file
            .write_all(virtualized.as_bytes())
            .and_then(|_| file.sync_all());
        if let Err(e) = write_res {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(format!("Failed to write virtualized ghost file: {}", e));
        }
        drop(file);

        crate::vault::atomic_replace_file(&temp_path, &out_path)?;

        println!(
            "👻 Generated Ghost File: {} (Virtualised {} unique live credentials)",
            out_path.display(),
            count
        );
        Ok(out_path)
    }

    pub fn virtualize_file(
        target_file: &Path,
        engine: &SecretGuardEngine,
    ) -> Result<PathBuf, String> {
        Self::virtualize_file_with_options(target_file, engine, false)
    }

    /// Best-effort overwrite with zeroes + sync + unlink of the Ghost session file, failing closed on errors.
    pub fn purge_session() -> Result<(), String> {
        let path = Self::try_get_session_path()?;
        let _lock = GhostLockGuard::acquire(&path)?;

        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Security Error: Ghost session path '{}' is a symlink. Refusing to overwrite.",
                        path.display()
                    ));
                }
                let len = (meta.len() as usize).max(256);
                let zeroes = vec![0u8; len];
                let mut open_opts = fs::OpenOptions::new();
                open_opts.write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    open_opts.custom_flags(libc::O_NOFOLLOW);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::OpenOptionsExt;
                    // FILE_FLAG_OPEN_REPARSE_POINT (0x00200000) prevents following reparse points/symlinks
                    open_opts.custom_flags(0x0020_0000);
                }
                let mut f = open_opts
                    .open(&path)
                    .map_err(|e| format!("Failed to open Ghost session file for purge: {}", e))?;
                f.write_all(&zeroes)
                    .and_then(|_| f.sync_all())
                    .map_err(|e| format!("Failed to overwrite Ghost session file: {}", e))?;
                drop(f);
                fs::remove_file(&path)
                    .map_err(|e| format!("Failed to remove Ghost session file: {}", e))?;
                if path.exists() {
                    return Err(format!(
                        "Ghost session file '{}' still exists after removal.",
                        path.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!(
                    "Failed to inspect Ghost session file for purge: {}",
                    e
                ));
            }
        }
        Ok(())
    }

    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard ghost - Client-Side LLM Context Virtualization & Sanitization
Generates polymorphic Ghost Tokens in a sanitized copy (.ghost) so AI agents
and prompts can operate safely without exposing real credentials.

SECURITY MODEL & ARCHITECTURAL NOTICE:
    'virtualize' generates an atomically written, sanitized copy (.ghost) alongside
    the original file. It does NOT remove or enforce OS boundaries on the original file.
    Session mappings are encrypted at rest with AES-256-GCM using a key derived from
    your local SecretGuard master key.

USAGE:
    secretguard ghost virtualize <FILE> [--fresh]  Creates .ghost sanitized file safe for AI prompts
    secretguard ghost inspect                      Displays active ghost tokens in session table
    secretguard ghost purge [--force]              Clears, overwrites, and unlinks the session file
"#
            );
            return;
        }

        match args[0].as_str() {
            "virtualize" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard ghost virtualize <FILE> [--fresh]");
                    std::process::exit(2);
                }
                let fresh = args.iter().any(|a| a == "--fresh");
                let target_arg = args[1..]
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .map(|s| s.as_str());
                let Some(target_str) = target_arg else {
                    eprintln!("Usage: secretguard ghost virtualize <FILE> [--fresh]");
                    std::process::exit(2);
                };
                if let Err(e) =
                    Self::virtualize_file_with_options(Path::new(target_str), engine, fresh)
                {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
            "inspect" => {
                let path = match Self::try_get_session_path() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let session = match Self::try_load_session() {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("❌ Error (failing closed): {}", e);
                        std::process::exit(1);
                    }
                };
                let acl_desc = if cfg!(windows) {
                    "Windows NTFS DACL (Owner/Administrators/SYSTEM)"
                } else {
                    "Restricted 0600"
                };
                println!("👻 SecretGuard Ghost Session Table (AES-256-GCM Encrypted at Rest):");
                println!("─────────────────────────────────────────────────────────────────");
                if session.mappings.is_empty() {
                    println!("  No active ghost token mappings in session.");
                } else {
                    let mut keys: Vec<&String> = session.mappings.keys().collect();
                    keys.sort();
                    for ghost in keys {
                        println!("  {}  ──►  [AES-256-GCM ENCRYPTED ON DISK]", ghost);
                    }
                }
                println!("─────────────────────────────────────────────────────────────────");
                println!("Total Virtualized Mappings: {}", session.mappings.len());
                println!(
                    "Storage Path:               {} ({})",
                    path.display(),
                    acl_desc
                );
            }
            "purge" => {
                if let Err(e) = Self::purge_session() {
                    eprintln!("❌ Purge failed: {}", e);
                    std::process::exit(1);
                }
                println!("✨ Active ghost session mappings cleared, file overwritten with zeroes and unlinked (note: SSDs, journaling filesystems, and snapshots may retain prior blocks).");
            }
            _ => {
                eprintln!(
                    "Unknown ghost command: {}. Run 'secretguard ghost --help'",
                    args[0]
                );
                std::process::exit(2);
            }
        }
    }
}
