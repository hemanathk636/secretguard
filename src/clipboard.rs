use crate::SecretGuardEngine;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClipboardStatus {
    pub monitored: bool,
    pub secrets_intercepted: usize,
    pub last_cleared: Option<String>,
}

#[derive(Default)]
pub struct ClipboardGuardian;

impl ClipboardGuardian {
    pub fn new() -> Self {
        Self
    }

    /// Simulates inspecting clipboard text and wiping if high-risk secret is detected
    pub fn sanitize_clipboard_payload(text: &str, engine: &SecretGuardEngine) -> (bool, String) {
        let res = engine.scan_and_sanitize(text);
        if res.has_secret {
            (true, res.sanitized_text)
        } else {
            (false, text.to_string())
        }
    }

    /// Read text from OS clipboard
    #[cfg(target_os = "windows")]
    pub fn get_system_clipboard() -> Option<String> {
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Clipboard"])
            .output()
            .ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_system_clipboard() -> Option<String> {
        // macOS pbpaste / Linux xclip
        let output = std::process::Command::new("pbpaste").output().ok();
        if let Some(out) = output {
            if out.status.success() {
                return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
        }
        None
    }

    /// Clear OS clipboard
    #[cfg(target_os = "windows")]
    pub fn clear_system_clipboard() {
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Set-Clipboard -Value ''"])
            .output();
    }

    #[cfg(not(target_os = "windows"))]
    pub fn clear_system_clipboard() {
        let _ = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::null())
            .output();
    }

    /// CLI Handler for `secretguard clipboard`
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if !args.is_empty() && (args[0] == "--help" || args[0] == "-h") {
            eprintln!(
                r#"secretguard clipboard - OS Clipboard Privacy Guardian

USAGE:
    secretguard clipboard watch [--timeout 30]   Monitors OS clipboard and wipes secrets after N seconds
    secretguard clipboard clean                  Instantly scans and purges any secret currently on clipboard
"#
            );
            return;
        }

        let subcommand = if !args.is_empty() {
            args[0].as_str()
        } else {
            "clean"
        };

        match subcommand {
            "clean" => {
                println!("📋 Inspecting OS clipboard...");
                if let Some(text) = Self::get_system_clipboard() {
                    let (detected, sanitized) = Self::sanitize_clipboard_payload(&text, engine);
                    if detected {
                        Self::clear_system_clipboard();
                        println!("🚨 Exposed secret detected on clipboard!");
                        println!("🧹 Clipboard wiped cleanly. Sanitized value was: \x1b[33m{}\x1b[0m", sanitized);
                    } else {
                        println!("✅ OS clipboard is clean. Zero secrets exposed.");
                    }
                } else {
                    println!("ℹ️ Unable to access clipboard or clipboard is empty.");
                }
            }
            "watch" => {
                let timeout_secs: u64 = if args.len() >= 3 && args[1] == "--timeout" {
                    args[2].parse().unwrap_or(30)
                } else {
                    30
                };

                println!("🛡️ Clipboard Privacy Guardian running (Self-destruct timer: {}s)...", timeout_secs);
                println!("Press Ctrl+C to stop.");

                let mut last_seen = String::new();
                loop {
                    if let Some(text) = Self::get_system_clipboard() {
                        if text != last_seen && !text.is_empty() {
                            last_seen = text.clone();
                            let (has_secret, _) = Self::sanitize_clipboard_payload(&text, engine);
                            if has_secret {
                                println!("🚨 Secret copied to clipboard! Starting {}s countdown before purge...", timeout_secs);
                                thread::sleep(Duration::from_secs(timeout_secs));
                                Self::clear_system_clipboard();
                                println!("🧹 Clipboard auto-purged by SecretGuard Guardian.");
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(500));
                }
            }
            _ => {
                eprintln!("Unknown subcommand: {}. Use 'clean' or 'watch'.", subcommand);
                std::process::exit(2);
            }
        }
    }
}
