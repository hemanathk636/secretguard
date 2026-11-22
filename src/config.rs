use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPatternConfig {
    pub name: String,
    pub regex: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretGuardConfig {
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default)]
    pub custom_patterns: Vec<CustomPatternConfig>,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

fn default_entropy_threshold() -> f64 {
    3.6
}

impl Default for SecretGuardConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.6,
            custom_patterns: Vec::new(),
            whitelist: Vec::new(),
        }
    }
}

impl SecretGuardConfig {
    /// Search for configuration file in current directory or user home
    pub fn locate_config_file() -> Option<PathBuf> {
        let local = Path::new("secretguard.toml");
        if local.exists() {
            return Some(local.to_path_buf());
        }

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let global = Path::new(&home).join(".secretguard").join("config.toml");
        if global.exists() {
            return Some(global);
        }

        None
    }

    /// Load configuration from disk, or return default
    pub fn load() -> Self {
        if let Some(path) = Self::locate_config_file() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = toml_parse(&content) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    /// Generate a well-documented starter configuration file
    pub fn generate_template(path: &Path) -> std::io::Result<()> {
        let template = r#"# SecretGuard Configuration File
# Documentation: https://hemanathk636.github.io/secretguard/

# Minimum Shannon entropy threshold for high-randomness string detection (Default: 3.6)
entropy_threshold = 3.6

# Whitelist strings, test tokens, or hashes to prevent false positives
whitelist = [
    "example_safe_token_1234567890",
    "sha256:0123456789abcdef0123456789abcdef",
]

# Custom company or proprietary credential patterns
[[custom_patterns]]
name = "Internal Enterprise Token"
regex = "\\b(corp_tok|internal_sec)_[a-zA-Z0-9]{24,}\\b"
description = "Internal enterprise infrastructure API token"

[[custom_patterns]]
name = "Custom Database DSN"
regex = "customdb://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+"
description = "Custom proprietary database connection string"
"#;
        fs::write(path, template)
    }

    /// CLI entrypoint for secretguard config
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            println!(
                r#"SecretGuard Configuration Manager

USAGE:
    secretguard config <SUBCOMMAND>

SUBCOMMANDS:
    init              Generate starter 'secretguard.toml' in current directory
    show              Display active configuration, loaded patterns & whitelists
    path              Print location of active config file
"#
            );
            return;
        }

        match args[0].as_str() {
            "init" => {
                let target = Path::new("secretguard.toml");
                if target.exists() {
                    println!("ℹ️  'secretguard.toml' already exists in current directory.");
                    return;
                }
                if let Err(e) = Self::generate_template(target) {
                    eprintln!("❌ Failed to create config file: {}", e);
                    std::process::exit(1);
                }
                println!("✨ Successfully created 'secretguard.toml'!");
                println!("📝 You can now add custom regex patterns and whitelist strings to prevent false positives.");
            }
            "show" => {
                let cfg = Self::load();
                println!("⚙️  Active SecretGuard Configuration");
                println!("────────────────────────────────────────────");
                println!(
                    "Config File:       {}",
                    Self::locate_config_file()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "None (Using built-in defaults)".to_string())
                );
                println!("Entropy Threshold: {}", cfg.entropy_threshold);
                println!("Custom Patterns:   {}", cfg.custom_patterns.len());
                for p in &cfg.custom_patterns {
                    println!("   • {} -> '{}'", p.name, p.regex);
                }
                println!("Whitelisted Rules: {}", cfg.whitelist.len());
                for w in &cfg.whitelist {
                    println!("   • {}", w);
                }
            }
            "path" => {
                if let Some(p) = Self::locate_config_file() {
                    println!("{}", p.display());
                } else {
                    println!("No config file found (running with built-in defaults).");
                }
            }
            _ => {
                eprintln!(
                    "Unknown config subcommand: '{}'. Run 'secretguard config --help'",
                    args[0]
                );
                std::process::exit(1);
            }
        }
    }
}

/// Simple hand-crafted zero-dependency TOML parser for config
fn toml_parse(content: &str) -> Result<SecretGuardConfig, String> {
    let mut config = SecretGuardConfig::default();
    let mut current_pattern: Option<CustomPatternConfig> = None;
    let mut in_whitelist = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[[custom_patterns]]" {
            if let Some(p) = current_pattern.take() {
                if !p.name.is_empty() && !p.regex.is_empty() {
                    config.custom_patterns.push(p);
                }
            }
            current_pattern = Some(CustomPatternConfig {
                name: String::new(),
                regex: String::new(),
                description: None,
            });
            in_whitelist = false;
            continue;
        }

        if line.starts_with("entropy_threshold") {
            if let Some(val_str) = line.split('=').nth(1) {
                if let Ok(val) = val_str.trim().parse::<f64>() {
                    config.entropy_threshold = val;
                }
            }
            continue;
        }

        if line.starts_with("whitelist") && line.contains('[') {
            in_whitelist = true;
            if line.contains(']') {
                // Single line whitelist
                let inner = line
                    .split('[')
                    .nth(1)
                    .and_then(|s| s.split(']').next())
                    .unwrap_or("");
                for item in inner.split(',') {
                    let clean = item.trim().trim_matches('"').trim_matches('\'').trim();
                    if !clean.is_empty() {
                        config.whitelist.push(clean.to_string());
                    }
                }
                in_whitelist = false;
            }
            continue;
        }

        if in_whitelist {
            if line.contains(']') {
                in_whitelist = false;
                continue;
            }
            let clean = line
                .trim_matches(',')
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim();
            if !clean.is_empty() {
                config.whitelist.push(clean.to_string());
            }
            continue;
        }

        if let Some(ref mut p) = current_pattern {
            if line.starts_with("name") {
                if let Some(v) = line.split('=').nth(1) {
                    p.name = v.trim().trim_matches('"').trim_matches('\'').to_string();
                }
            } else if line.starts_with("regex") {
                if let Some(v) = line.split('=').nth(1) {
                    p.regex = v.trim().trim_matches('"').trim_matches('\'').to_string();
                }
            } else if line.starts_with("description") {
                if let Some(v) = line.split('=').nth(1) {
                    p.description = Some(v.trim().trim_matches('"').trim_matches('\'').to_string());
                }
            }
        }
    }

    if let Some(p) = current_pattern {
        if !p.name.is_empty() && !p.regex.is_empty() {
            config.custom_patterns.push(p);
        }
    }

    Ok(config)
}
