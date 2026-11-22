use crate::SecretGuardEngine;
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScreenShareStatus {
    pub active_sharing_detected: bool,
    pub detected_app: Option<String>,
}

pub struct ScreenShield;

impl ScreenShield {
    /// Detects if popular conferencing/meeting apps with screen-sharing capabilities are currently running
    pub fn is_meeting_or_sharing_active() -> ScreenShareStatus {
        let targets = [
            "zoom", "teams", "discord", "slack", "meet", "webex", "obs64", "obs", "skype",
        ];

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "Get-Process | Select-Object -ExpandProperty ProcessName",
                ])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for target in &targets {
                    if stdout.lines().any(|l| l.trim() == *target) {
                        return ScreenShareStatus {
                            active_sharing_detected: true,
                            detected_app: Some(target.to_string()),
                        };
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = Command::new("ps").args(["-A", "-o", "comm="]).output();
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
                for target in &targets {
                    if stdout.lines().any(|l| l.contains(target)) {
                        return ScreenShareStatus {
                            active_sharing_detected: true,
                            detected_app: Some(target.to_string()),
                        };
                    }
                }
            }
        }

        ScreenShareStatus {
            active_sharing_detected: false,
            detected_app: None,
        }
    }

    /// Masks any suspicious credential, URL password, or sensitive variable into high-visibility privacy blocks
    pub fn mask_screen_line(line: &str, engine: &SecretGuardEngine, force_shield: bool) -> String {
        let status = if force_shield {
            ScreenShareStatus {
                active_sharing_detected: true,
                detected_app: Some("Manual Shield".to_string()),
            }
        } else {
            Self::is_meeting_or_sharing_active()
        };

        if status.active_sharing_detected {
            let res = engine.scan_and_sanitize(line);
            if res.has_secret {
                // High-visibility block masking for screen shares
                format!(
                    "\x1b[41;37;1m 🛡️ [SCREEN-SHIELD BLURRED] \x1b[0m {}",
                    res.sanitized_text
                )
            } else {
                line.to_string()
            }
        } else {
            line.to_string()
        }
    }

    /// CLI Handler for `secretguard shield`
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard shield - Live Screen-Share Privacy Shield

USAGE:
    secretguard shield status                   Checks if Zoom, Teams, Discord or Meet are active
    secretguard shield run <COMMAND...>         Executes command with live screen-share blurred output
    secretguard shield auto                     Runs background watcher and warns on screen share
"#
            );
            return;
        }

        match args[0].as_str() {
            "status" => {
                let status = Self::is_meeting_or_sharing_active();
                println!("📺 Screen-Share Radar Status:");
                if status.active_sharing_detected {
                    println!(
                        "  • State:   \x1b[33mACTIVE MEETING DETECTED\x1b[0m (App: \x1b[1m{}\x1b[0m)",
                        status.detected_app.unwrap_or_default()
                    );
                    println!("  • Shield:  \x1b[32mENABLED (All terminal outputs will be blurred)\x1b[0m");
                } else {
                    println!("  • State:   \x1b[32mNo active screen share detected\x1b[0m");
                    println!("  • Shield:  Standby");
                }
            }
            "run" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard shield run <COMMAND...>");
                    std::process::exit(2);
                }

                let child_cmd = &args[1];
                let child_args = &args[2..];

                println!(
                    "🛡️ Screen-Share Privacy Shield active for command: \x1b[36m{} {}\x1b[0m\n",
                    child_cmd,
                    child_args.join(" ")
                );

                let mut child = Command::new(child_cmd)
                    .args(child_args)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("Failed to spawn child process");

                if let Some(stdout) = child.stdout.take() {
                    let reader = io::BufReader::new(stdout);
                    let stdout_handle = io::stdout();
                    let mut handle = stdout_handle.lock();

                    for line in reader.lines().flatten() {
                        let masked = Self::mask_screen_line(&line, engine, true);
                        writeln!(handle, "{}", masked).unwrap();
                    }
                }

                let status = child.wait().expect("Child process wasn't running");
                std::process::exit(status.code().unwrap_or(0));
            }
            "auto" => {
                println!("🛡️ SecretGuard Ambient Screen Shield Watcher running...");
                println!("Press Ctrl+C to stop.");
                let mut last_state = false;
                loop {
                    let st = Self::is_meeting_or_sharing_active();
                    if st.active_sharing_detected != last_state {
                        last_state = st.active_sharing_detected;
                        if last_state {
                            println!("\n🚨 Meeting application started: \x1b[33m{}\x1b[0m! Terminal Privacy Shield is now \x1b[32mARMED\x1b[0m.", st.detected_app.unwrap_or_default());
                        } else {
                            println!("\n✅ Meeting application closed. Terminal Privacy Shield on standby.");
                        }
                    }
                    thread::sleep(Duration::from_secs(3));
                }
            }
            _ => {
                eprintln!(
                    "Unknown subcommand: {}. Use 'status', 'run', or 'auto'.",
                    args[0]
                );
                std::process::exit(2);
            }
        }
    }
}
