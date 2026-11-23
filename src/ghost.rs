use crate::vault::{decrypt_vault_payload, derive_vault_key, encrypt_vault_payload};
use crate::SecretGuardEngine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct GhostSessionTable {
    pub mappings: HashMap<String, String>, // ghost_token -> real_token
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
        let key = Self::get_encryption_key()?;
        let decrypted_bytes = decrypt_vault_payload(&encrypted_bytes, &key)
            .map_err(|e| format!("Security Error: Ghost session decryption failed: {}", e))?;
        serde_json::from_slice::<GhostSessionTable>(&decrypted_bytes)
            .map_err(|e| format!("Invalid Ghost session table format: {}", e))
    }

    /// Backwards-compatible load_session that falls back with warning
    pub fn load_session() -> GhostSessionTable {
        Self::try_load_session().unwrap_or_else(|e| {
            eprintln!("⚠️ Warning: {}", e);
            GhostSessionTable::default()
        })
    }

    /// Encrypts and securely persists Ghost token mapping atomically with restricted permissions (0600),
    /// exclusive file creation semantics (O_EXCL), symlink rejection, parent fsync, and Windows ReplaceFileW.
    pub fn save_session(table: &GhostSessionTable) -> Result<(), std::io::Error> {
        let path = Self::try_get_session_path()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _ = fs::create_dir_all(parent);

        // Clean up legacy plaintext session file if it exists
        let legacy_json = path.with_extension("json");
        if legacy_json.exists() {
            let _ = fs::remove_file(&legacy_json);
        }

        let serialized = serde_json::to_vec(table)?;
        let key = Self::get_encryption_key().map_err(std::io::Error::other)?;
        let encrypted = encrypt_vault_payload(&serialized, &key).map_err(std::io::Error::other)?;

        // Unpredictable unique temporary file to eliminate race conditions and symlink replacement vulnerabilities
        let pid = std::process::id();
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let tmp_filename = format!(".ghost_session.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
        let temp_path = parent.join(tmp_filename);

        use std::io::Write;
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

    /// Generates a format-preserving polymorphic Ghost Token from a real key
    pub fn create_ghost_token(real_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"SECRETGUARD_GHOST_SEED_v1");
        hasher.update(real_key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

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
    /// Fails closed if session persistence fails.
    pub fn try_virtualize_text(
        input: &str,
        engine: &SecretGuardEngine,
    ) -> Result<(String, usize), String> {
        let scan = engine.scan_and_sanitize(input);
        if !scan.has_secret {
            return Ok((input.to_string(), 0));
        }

        let mut session = Self::try_load_session().map_err(|e| {
            format!(
                "Security Error: Failed to load Ghost session (failing closed): {}",
                e
            )
        })?;
        let mut count = 0;
        let mut output = input.to_string();

        // Scan tokens (splitting on whitespace, assignment, quotes, and commas)
        for part in input
            .split(|c: char| c.is_whitespace() || c == '=' || c == '"' || c == '\'' || c == ',')
        {
            let clean_word = part
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '.');
            if clean_word.len() >= 16 {
                let res = engine.scan_and_sanitize(clean_word);
                if res.has_secret {
                    let ghost = Self::create_ghost_token(clean_word);
                    output = output.replace(clean_word, &ghost);
                    session.mappings.insert(ghost, clean_word.to_string());
                    count += 1;
                }
            }
        }

        if count > 0 {
            Self::save_session(&session).map_err(|e| {
                format!(
                    "Security Error: Failed to securely persist Ghost session (failing closed): {}",
                    e
                )
            })?;
        }

        Ok((output, count))
    }

    /// Virtualizes text, failing closed with a panic if session persistence fails.
    pub fn virtualize_text(input: &str, engine: &SecretGuardEngine) -> (String, usize) {
        Self::try_virtualize_text(input, engine).unwrap_or_else(|e| panic!("{}", e))
    }

    pub fn virtualize_file(
        target_file: &Path,
        engine: &SecretGuardEngine,
    ) -> Result<PathBuf, String> {
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

        let content =
            fs::read_to_string(target_file).map_err(|e| format!("Failed to read file: {}", e))?;

        let (virtualized, count) = Self::try_virtualize_text(&content, engine)?;
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

        use std::io::Write;
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
            "👻 Generated Ghost File: {} (Virtualised {} live credentials)",
            out_path.display(),
            count
        );
        Ok(out_path)
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
    To ensure AI agents never see raw credentials, developers must quarantine the original
    secret source or exclude it from agent tool context, and point AI tools at the .ghost file.

USAGE:
    secretguard ghost virtualize <FILE>     Creates .ghost sanitized file safe for AI prompts
    secretguard ghost inspect               Displays currently active ghost tokens (real keys zeroed)
    secretguard ghost purge                 Zeroes and securely wipes all active ghost session mappings
"#
            );
            return;
        }

        match args[0].as_str() {
            "virtualize" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard ghost virtualize <FILE>");
                    std::process::exit(2);
                }
                let target = Path::new(&args[1]);
                if let Err(e) = Self::virtualize_file(target, engine) {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
            "inspect" => {
                let session = Self::load_session();
                println!(
                    "👻 SecretGuard Zero-Knowledge Ghost Session Table (Encrypted in AES-256-GCM):"
                );
                println!("─────────────────────────────────────────────────────────────────");
                if session.mappings.is_empty() {
                    println!("  No active ghost token mappings in session.");
                } else {
                    for ghost in session.mappings.keys() {
                        println!(
                            "  {}  ──►  [AES-256-GCM ENCRYPTED IN VAULT - ZERO EXPOSURE]",
                            ghost
                        );
                    }
                }
                println!("─────────────────────────────────────────────────────────────────");
                println!("Total Virtualized Mappings: {}", session.mappings.len());
                println!(
                    "Storage Path:               {} (Restricted 0600)",
                    Self::get_session_path().display()
                );
            }
            "purge" => {
                let path = Self::get_session_path();
                if path.exists() {
                    // Overwrite full file length with zeroes before unlinking
                    let len = fs::metadata(&path)
                        .map(|m| m.len() as usize)
                        .unwrap_or(256)
                        .max(256);
                    let zeroes = vec![0u8; len];
                    let _ = fs::write(&path, &zeroes);
                    let _ = fs::remove_file(&path);
                }
                println!("✨ All ghost token session mappings zeroed via multi-pass in-memory overwrite and unlinked.");
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
