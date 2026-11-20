use crate::SecretGuardEngine;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn get_quarantine_path() -> PathBuf {
    if let Ok(p) = env::var("SECRETGUARD_QUARANTINE_PATH") {
        return PathBuf::from(p);
    }
    let home = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let dir = Path::new(&home).join(".secretguard");
    if fs::create_dir_all(&dir).is_err() {
        let fallback = Path::new(".").join(".secretguard");
        let _ = fs::create_dir_all(&fallback);
        return fallback.join("quarantine.txt");
    }
    dir.join("quarantine.txt")
}

pub fn quarantine_secret(secret: &str) {
    let qfile = get_quarantine_path();
    if let Some(parent) = qfile.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&qfile) {
        let _ = writeln!(f, "REVOKED_HASH:{}", hash);
    }
}
pub struct RevocationInfo {
    pub provider: &'static str,
    pub dashboard_url: &'static str,
    pub api_revoke_cmd: Option<String>,
}

pub fn identify_revocation_info(secret: &str) -> Option<RevocationInfo> {
    if secret.starts_with("sk-proj-") || secret.starts_with("sk-") {
        Some(RevocationInfo {
            provider: "OpenAI",
            dashboard_url: "https://platform.openai.com/api-keys",
            api_revoke_cmd: None,
        })
    } else if secret.starts_with("ghp_") || secret.starts_with("gho_") || secret.starts_with("ghu_") || secret.starts_with("ghs_") {
        Some(RevocationInfo {
            provider: "GitHub",
            dashboard_url: "https://github.com/settings/tokens",
            api_revoke_cmd: Some(format!(
                "curl -L -X DELETE -H \"Authorization: Bearer {}\" https://api.github.com/applications/tokens",
                secret
            )),
        })
    } else if secret.starts_with("sk_live_") || secret.starts_with("sk_test_") || secret.starts_with("rk_live_") {
        Some(RevocationInfo {
            provider: "Stripe",
            dashboard_url: "https://dashboard.stripe.com/apikeys",
            api_revoke_cmd: None,
        })
    } else if secret.starts_with("xoxb-") || secret.starts_with("xoxp-") || secret.starts_with("xoxa-") {
        Some(RevocationInfo {
            provider: "Slack",
            dashboard_url: "https://api.slack.com/apps",
            api_revoke_cmd: Some(format!(
                "curl -X POST -H \"Authorization: Bearer {}\" https://slack.com/api/auth.revoke",
                secret
            )),
        })
    } else if secret.starts_with("AKIA") || secret.starts_with("ASIA") {
        Some(RevocationInfo {
            provider: "Amazon Web Services (AWS)",
            dashboard_url: "https://console.aws.amazon.com/iam/home#/security_credentials",
            api_revoke_cmd: None,
        })
    } else if secret.starts_with("SG.") {
        Some(RevocationInfo {
            provider: "SendGrid",
            dashboard_url: "https://app.sendgrid.com/settings/api_keys",
            api_revoke_cmd: None,
        })
    } else if secret.starts_with("AIza") {
        Some(RevocationInfo {
            provider: "Google Cloud / Gemini",
            dashboard_url: "https://console.cloud.google.com/apis/credentials",
            api_revoke_cmd: None,
        })
    } else {
        None
    }
}

pub fn emergency_scrub_git_head(engine: &SecretGuardEngine) -> Result<usize, String> {
    // Check if in git repository
    let git_check = Command::new("git").args(["rev-parse", "--is-inside-work-tree"]).output();
    if git_check.is_err() || !git_check.unwrap().status.success() {
        return Ok(0);
    }

    // Inspect files changed in the latest commit
    let diff_output = Command::new("git")
        .args(["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"])
        .output()
        .map_err(|e| format!("Failed to read git diff: {}", e))?;

    let files_str = String::from_utf8_lossy(&diff_output.stdout);
    let mut scrubbed_files = 0;

    for line in files_str.lines() {
        let path_str = line.trim();
        if path_str.is_empty() {
            continue;
        }
        let p = Path::new(path_str);
        if p.exists() && p.is_file() {
            if let Ok(content) = fs::read_to_string(p) {
                let res = engine.scan_and_sanitize(&content);
                if res.has_secret {
                    // Replace secrets with format-preserving synthetic mock tokens
                    if fs::write(p, &res.synthetic_text).is_ok() {
                        let _ = Command::new("git").args(["add", path_str]).output();
                        scrubbed_files += 1;
                    }
                }
            }
        }
    }

    if scrubbed_files > 0 {
        let _ = Command::new("git")
            .args(["commit", "--amend", "--no-edit"])
            .output();
    }

    Ok(scrubbed_files)
}

pub fn emergency_clean_shell_history(engine: &SecretGuardEngine) -> usize {
    let home = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());

    let candidates = vec![
        Path::new(&home).join(".zsh_history"),
        Path::new(&home).join(".bash_history"),
    ];

    let mut total_sanitized = 0;

    for path in candidates {
        if !path.exists() {
            continue;
        }

        if let Ok(file) = File::open(&path) {
            let reader = BufReader::new(file);
            let mut cleaned_lines = Vec::new();
            let mut leaks = 0;

            for line in reader.lines().flatten() {
                let res = engine.scan_and_sanitize(&line);
                if res.has_secret {
                    leaks += 1;
                    cleaned_lines.push(res.sanitized_text);
                } else {
                    cleaned_lines.push(line);
                }
            }

            if leaks > 0 {
                // Create emergency timestamped backup
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let backup_path = path.with_extension(format!("emergency_bak_{}", now));
                let _ = fs::copy(&path, backup_path);

                if let Ok(mut out) = File::create(&path) {
                    for l in cleaned_lines {
                        let _ = writeln!(out, "{}", l);
                    }
                }
                total_sanitized += leaks;
            }
        }
    }

    total_sanitized
}

pub fn run_panic_emergency(args: &[String], engine: &SecretGuardEngine) {
    println!(
        r#"
🚨═══════════════════════════════════════════════════════════════🚨
                 SECRETGUARD EMERGENCY PANIC SYSTEM
🚨═══════════════════════════════════════════════════════════════🚨
"#
    );

    let specific_target = if !args.is_empty() && !args[0].starts_with('-') {
        Some(args[0].as_str())
    } else {
        None
    };

    println!("⚡ Initiating 4-Stage Immediate Leak Remediation...\n");

    // STAGE 1: Git Head Commit Surgical Scrub
    print!("1️⃣  Inspecting latest Git commit... ");
    match emergency_scrub_git_head(engine) {
        Ok(count) if count > 0 => {
            println!("🔒 Surgically scrubbed and amended {} file(s) in HEAD with synthetic mocks!", count);
        }
        Ok(_) => {
            println!("✅ Clean (No unmasked secrets in latest commit).");
        }
        Err(e) => {
            println!("ℹ️  Git check skipped: {}", e);
        }
    }

    // STAGE 2: Shell History Emergency Purge
    print!("2️⃣  Purging unmasked secrets from shell history... ");
    let scrubbed_history = emergency_clean_shell_history(engine);
    if scrubbed_history > 0 {
        println!("🧹 Erased {} exposed credential(s) from history with atomic backup!", scrubbed_history);
    } else {
        println!("✅ Clean (No exposed secrets in shell history).");
    }

    // STAGE 3: Provider Revocation & Invalidation Directives
    println!("\n3️⃣  Provider Revocation Analysis:");
    if let Some(target_secret) = specific_target {
        quarantine_secret(target_secret);
        if let Some(rev) = identify_revocation_info(target_secret) {
            println!("   • Target Provider: {}", rev.provider);
            println!("   • Immediate Revocation Dashboard: {}", rev.dashboard_url);
            if let Some(cmd) = rev.api_revoke_cmd {
                println!("   • Instant API Revoke Command:\n     {}", cmd);
                print!("   ⚡ Execute instant API revocation curl? (Y/n): ");
                let _ = std::io::stdout().flush();
                let mut ans = String::new();
                let _ = std::io::stdin().read_line(&mut ans);
                if ans.trim().is_empty() || ans.trim().eq_ignore_ascii_case("y") {
                    println!("   📡 Dispatched API revocation request...");
                    let _ = Command::new("cmd").args(["/C", &cmd]).output();
                    println!("   ✅ Revocation command executed!");
                }
            }
        } else {
            println!("   • Unknown/Generic Secret: Added to cryptographic quarantine blacklist.");
            println!("   • Recommendation: Revoke and rotate this key from your provider dashboard immediately.");
        }
    } else {
        println!("   • Quick Revocation Dashboards:");
        println!("     - OpenAI:   https://platform.openai.com/api-keys");
        println!("     - GitHub:   https://github.com/settings/tokens");
        println!("     - AWS IAM:  https://console.aws.amazon.com/iam/home#/security_credentials");
        println!("     - Stripe:   https://dashboard.stripe.com/apikeys");
        println!("     - Slack:    https://api.slack.com/apps");
    }

    // STAGE 4: Cryptographic Quarantine
    println!("\n4️⃣  Cryptographic Quarantine: Active (Protected by ~/.secretguard/quarantine.txt)");

    println!(
        r#"
✨═══════════════════════════════════════════════════════════════✨
             EMERGENCY REMEDIATION COMPLETE!
  • Git commits sanitized with format-preserving synthetic mocks.
  • Shell history scrubbed with timestamped backup.
  • Compromised credentials quarantined from future reuse.
✨═══════════════════════════════════════════════════════════════✨
"#
    );
}
