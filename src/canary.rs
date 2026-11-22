use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CanaryToken {
    pub token_type: String,
    pub token_value: String,
    pub tripwire_hash: String,
    pub plant_location: String,
    pub instructions: String,
}

pub struct CanaryManager;

impl CanaryManager {
    /// Generates authentic-looking decoy credentials
    pub fn generate_canary(token_type: &str, memo: &str) -> CanaryToken {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", timestamp, memo).as_bytes());
        let hash_hex = format!("{:x}", hasher.finalize());

        let token_val = match token_type {
            "aws" => format!("AKIA{}", hash_hex[..16].to_uppercase()),
            "github" => format!("ghp_CANARY_{}", &hash_hex[..32]),
            "stripe" => format!("sk_test_CANARY_{}", &hash_hex[..24]),
            _ => format!("sk-proj-CANARY_{}", &hash_hex[..40]),
        };

        CanaryToken {
            token_type: token_type.to_string(),
            token_value: token_val,
            tripwire_hash: hash_hex[..16].to_string(),
            plant_location: String::new(),
            instructions: "Plant this decoy token into .env.example, git commits, or staging repos to detect unauthorized access.".to_string(),
        }
    }

    /// Plant canary tripwire into target file (e.g. .env.example or test config)
    pub fn plant_canary(file_path: &Path, token_type: &str) -> Result<CanaryToken, String> {
        let mut canary = Self::generate_canary(token_type, &file_path.display().to_string());
        canary.plant_location = file_path.display().to_string();

        let line_to_append = match token_type {
            "aws" => format!("AWS_ACCESS_KEY_ID={}\n", canary.token_value),
            "github" => format!("GITHUB_TOKEN={}\n", canary.token_value),
            "stripe" => format!("STRIPE_SECRET_KEY={}\n", canary.token_value),
            _ => format!("OPENAI_API_KEY={}\n", canary.token_value),
        };

        if let Some(parent) = file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .map_err(|e| format!("Failed to open target file: {}", e))?;

        file.write_all(line_to_append.as_bytes())
            .map_err(|e| format!("Failed to plant canary: {}", e))?;

        Ok(canary)
    }

    /// CLI Handler for `secretguard canary`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard canary - Canary & Honeytoken Tripwire Generator

USAGE:
    secretguard canary generate [aws|openai|github|stripe]
    secretguard canary plant <FILE> [TYPE]

Generates hyper-realistic decoy credentials to catch unauthorized clones,
AI prompt exfiltration, and malicious internal reconnaissance.
"#
            );
            return;
        }

        match args[0].as_str() {
            "generate" => {
                let token_type = if args.len() >= 2 { &args[1] } else { "openai" };
                let canary = Self::generate_canary(token_type, "adhoc");
                println!(
                    "🐤 Generated Honeytoken Tripwire ({})",
                    canary.token_type.to_uppercase()
                );
                println!("  • Decoy Secret:    \x1b[33m{}\x1b[0m", canary.token_value);
                println!(
                    "  • Tripwire Hash:   \x1b[36m{}\x1b[0m",
                    canary.tripwire_hash
                );
                println!("💡 {}", canary.instructions);
            }
            "plant" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard canary plant <FILE_PATH> [TYPE]");
                    std::process::exit(2);
                }
                let target = Path::new(&args[1]);
                let token_type = if args.len() >= 3 { &args[2] } else { "openai" };

                match Self::plant_canary(target, token_type) {
                    Ok(canary) => {
                        println!("🎉 Honeytoken tripwire successfully planted!");
                        println!("📁 Target File:   \x1b[32m{}\x1b[0m", canary.plant_location);
                        println!("🔑 Decoy Key:     \x1b[33m{}\x1b[0m", canary.token_value);
                        println!("🚨 Tripwire ID:   \x1b[36m{}\x1b[0m", canary.tripwire_hash);
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to plant canary: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!(
                    "Unknown subcommand: {}. Use 'generate' or 'plant'.",
                    args[0]
                );
                std::process::exit(2);
            }
        }
    }
}
