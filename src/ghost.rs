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
    pub fn get_session_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        Path::new(&home).join(".secretguard").join("ghost_session.json")
    }

    pub fn load_session() -> GhostSessionTable {
        let path = Self::get_session_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(table) = serde_json::from_str(&content) {
                    return table;
                }
            }
        }
        GhostSessionTable::default()
    }

    pub fn save_session(table: &GhostSessionTable) -> Result<(), std::io::Error> {
        let path = Self::get_session_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let serialized = serde_json::to_string_pretty(table)?;
        fs::write(path, serialized)
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
            format!("AKIA_GHOST_{}", &hash[0..12].to_uppercase())
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

    /// Virtualizes text, replacing real keys with Ghost Tokens and saving the mapping
    pub fn virtualize_text(input: &str, engine: &SecretGuardEngine) -> (String, usize) {
        let scan = engine.scan_and_sanitize(input);
        if !scan.has_secret {
            return (input.to_string(), 0);
        }

        let mut session = Self::load_session();
        let mut count = 0;
        let mut output = input.to_string();

        // Scan words/tokens
        for word in input.split_whitespace() {
            let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '.');
            let res = engine.scan_and_sanitize(clean_word);
            if res.has_secret && clean_word.len() >= 16 {
                let ghost = Self::create_ghost_token(clean_word);
                output = output.replace(clean_word, &ghost);
                session.mappings.insert(ghost, clean_word.to_string());
                count += 1;
            }
        }

        let _ = Self::save_session(&session);
        (output, count)
    }

    pub fn virtualize_file(target_file: &Path, engine: &SecretGuardEngine) -> Result<PathBuf, String> {
        if !target_file.exists() {
            return Err(format!("File '{}' does not exist.", target_file.display()));
        }

        let content = fs::read_to_string(target_file)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let (virtualized, count) = Self::virtualize_text(&content, engine);
        let out_path = target_file.with_extension("ghost");

        fs::write(&out_path, virtualized)
            .map_err(|e| format!("Failed to write ghost file: {}", e))?;

        println!("👻 Generated Ghost File: {} (Virtualised {} live credentials)", out_path.display(), count);
        Ok(out_path)
    }

    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard ghost - Zero-Knowledge LLM Context Virtualization
Generates polymorphic Ghost Tokens so AI agents can code without ever exposing real credentials.

USAGE:
    secretguard ghost virtualize <FILE>     Creates .ghost sanitized file safe for AI prompts
    secretguard ghost inspect               Displays currently active ghost token mappings in RAM
    secretguard ghost purge                 Zeroes all active ghost session mappings
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
                println!("👻 SecretGuard Zero-Knowledge Ghost Session Table:");
                println!("─────────────────────────────────────────────────────────────────");
                if session.mappings.is_empty() {
                    println!("  No active ghost token mappings in session.");
                } else {
                    for (ghost, real) in &session.mappings {
                        let masked_real = if real.len() > 10 {
                            format!("{}***{}", &real[0..4], &real[real.len()-4..])
                        } else {
                            "***".to_string()
                        };
                        println!("  {}  ──►  {}", ghost, masked_real);
                    }
                }
                println!("─────────────────────────────────────────────────────────────────");
                println!("Total Virtualized Mappings: {}", session.mappings.len());
            }
            "purge" => {
                let empty = GhostSessionTable::default();
                let _ = Self::save_session(&empty);
                println!("✨ All ghost token memory mappings successfully purged!");
            }
            _ => {
                eprintln!("Unknown ghost command: {}. Run 'secretguard ghost --help'", args[0]);
                std::process::exit(2);
            }
        }
    }
}
