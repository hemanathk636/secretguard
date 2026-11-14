use secretguard::SecretGuardEngine;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

fn print_usage() {
    eprintln!(
        r#"SecretGuard (v0.1.1) - Sub-millisecond Terminal Secret & Privacy Guard

USAGE:
    secretguard <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    check <STRING>      Scans input string; exits with 1 if secret detected, 0 if clean.
    sanitize <STRING>   Prints sanitized string; exits with 1 if redacted, 0 if clean.
    wrap <COMMAND...>   Executes command and sanitizes stdout stream in real time.
    audit [FILE]        Scans local shell history (.zsh_history / .bash_history) for historical leaks.
    clean-history       Safely scrubs exposed secrets from shell history with atomic backups.
    protect-agent [DIR] Shields workspace from AI coding agent (Claude Code, Cursor, MCP) leaks.
    hook <SHELL>        Prints the integration hook for (zsh | bash | fish | powershell).
"#
    );
}

fn run_audit(target_path: Option<&str>, engine: &SecretGuardEngine) {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());

    let file_path = if let Some(p) = target_path {
        PathBuf::from(p)
    } else {
        let zsh = Path::new(&home).join(".zsh_history");
        let bash = Path::new(&home).join(".bash_history");
        if zsh.exists() {
            zsh
        } else if bash.exists() {
            bash
        } else {
            eprintln!("❌ No .zsh_history or .bash_history found. Provide path: secretguard audit <PATH>");
            process::exit(1);
        }
    };

    println!("🔍 Auditing history file: {}\n", file_path.display());

    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open file: {}", e);
            process::exit(1);
        }
    };

    let reader = io::BufReader::new(file);
    let mut total_lines = 0;
    let mut leaks = 0;

    for (idx, line) in reader.lines().flatten().enumerate() {
        total_lines += 1;
        let res = engine.scan_and_sanitize(&line);
        if res.has_secret {
            leaks += 1;
            println!(
                "⚠️  [Line {}] Detected {:?}\n   Original: {}\n   Redacted: {}\n",
                idx + 1,
                res.matched_rules,
                line.trim(),
                res.sanitized_text.trim()
            );
        }
    }

    println!("────────────────────────────────────────────");
    println!("Total Commands Scanned: {}", total_lines);
    if leaks == 0 {
        println!("✅ Clean! Zero unmasked secrets found in history.");
    } else {
        println!("🚨 Found {} exposed credentials in your history file!", leaks);
    }
}

fn run_clean_history(target_path: Option<&str>, dry_run: bool, engine: &SecretGuardEngine) {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());

    let file_path = if let Some(p) = target_path {
        PathBuf::from(p)
    } else {
        let zsh = Path::new(&home).join(".zsh_history");
        let bash = Path::new(&home).join(".bash_history");
        if zsh.exists() {
            zsh
        } else if bash.exists() {
            bash
        } else {
            eprintln!("❌ No .zsh_history or .bash_history found. Provide path: secretguard clean-history <PATH>");
            process::exit(1);
        }
    };

    println!("🧹 SecretGuard History Sanitizer: {}", file_path.display());
    if dry_run {
        println!("ℹ️  Mode: DRY-RUN (Preview only, no files will be modified)\n");
    }

    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open history file: {}", e);
            process::exit(1);
        }
    };

    let reader = io::BufReader::new(file);
    let mut total_lines = 0;
    let mut sanitized_lines = Vec::new();
    let mut leaks_found = 0;

    for (idx, line_res) in reader.lines().enumerate() {
        match line_res {
            Ok(line) => {
                total_lines += 1;
                let res = engine.scan_and_sanitize(&line);
                if res.has_secret {
                    leaks_found += 1;
                    println!(
                        "⚠️  [Line {}] Found {:?}\n   Before: {}\n   After:  {}\n",
                        idx + 1,
                        res.matched_rules,
                        line.trim(),
                        res.sanitized_text.trim()
                    );
                    sanitized_lines.push(res.sanitized_text);
                } else {
                    sanitized_lines.push(line);
                }
            }
            Err(_) => {
                continue;
            }
        }
    }

    println!("────────────────────────────────────────────");
    println!("Total Commands Scanned: {}", total_lines);
    println!("Exposed Secrets Found:  {}", leaks_found);

    if leaks_found == 0 {
        println!("✅ Your history is already 100% clean! No changes needed.");
        return;
    }

    if dry_run {
        println!("\n💡 Dry-run complete. Run without '--dry-run' to apply changes safely.");
        return;
    }

    print!("\n⚠️  Safely sanitize {} exposed secrets in {}? (y/N): ", leaks_found, file_path.display());
    io::stdout().flush().unwrap();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap_or(0);

    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("Aborted. No changes were made.");
        return;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let backup_path = file_path.with_extension(format!("backup.{}", timestamp));

    if let Err(e) = std::fs::copy(&file_path, &backup_path) {
        eprintln!("❌ Failed to create safe backup at {}: {}", backup_path.display(), e);
        eprintln!("Aborting operation to prevent any data loss.");
        process::exit(1);
    }
    println!("📦 Safe backup created at: {}", backup_path.display());

    let temp_path = file_path.with_extension(format!("tmp.{}", timestamp));
    let write_result = (|| -> io::Result<()> {
        let mut tmp_file = File::create(&temp_path)?;
        for l in sanitized_lines {
            writeln!(tmp_file, "{}", l)?;
        }
        tmp_file.flush()?;
        tmp_file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        eprintln!("❌ Failed to write temporary file: {}", e);
        let _ = std::fs::remove_file(&temp_path);
        process::exit(1);
    }

    if let Err(e) = std::fs::rename(&temp_path, &file_path) {
        eprintln!("❌ Failed to replace history file: {}", e);
        let _ = std::fs::remove_file(&temp_path);
        process::exit(1);
    }

    println!("✨ Successfully sanitized {} commands!", leaks_found);
    println!("🔒 Your history file is now safe. Backup preserved at: {}", backup_path.display());
}

fn run_protect_agent(target_dir: Option<&str>, engine: &SecretGuardEngine) {
    let base = Path::new(target_dir.unwrap_or("."));
    println!("🤖 SecretGuard AI Agent Shield: Inspecting '{}'...\n", base.display());

    let agent_targets = [
        ".claude/settings.local.json",
        ".claude/settings.json",
        ".mcp.json",
        "claude_desktop_config.json",
        ".aider.conf.yml",
        ".env",
        ".env.local",
    ];

    let mut found_issues = 0;

    for target in &agent_targets {
        let p = base.join(target);
        if p.exists() {
            println!("📄 Checking: {}", target);
            if let Ok(content) = std::fs::read_to_string(&p) {
                let res = engine.scan_and_sanitize(&content);
                if res.has_secret {
                    found_issues += 1;
                    println!("   🚨 Live secrets detected in {}: {:?}", target, res.matched_rules);
                } else {
                    println!("   ✅ No unmasked secrets detected.");
                }
            }
        }
    }

    let gitignore = base.join(".gitignore");
    if gitignore.exists() {
        if let Ok(gi_content) = std::fs::read_to_string(&gitignore) {
            let mut missing = Vec::new();
            if !gi_content.contains(".claude") {
                missing.push(".claude/");
            }
            if !gi_content.contains(".env") {
                missing.push(".env*");
            }
            if !missing.is_empty() {
                println!("\n⚠️  Git Leak Risk: Your .gitignore is missing protection for:");
                for m in &missing {
                    println!("   • {}", m);
                }
                println!("💡 Tip: Add them to .gitignore to prevent AI agents from pushing credentials!");
            } else {
                println!("\n✅ .gitignore protects .claude/ and .env* files.");
            }
        }
    } else {
        println!("\n⚠️  Warning: No .gitignore found in this directory.");
    }

    println!("\n────────────────────────────────────────────");
    if found_issues == 0 {
        println!("🛡️  Agent Shield: Workspace is safe from AI agent credential leaks!");
    } else {
        println!("🚨 Found {} AI agent files containing exposed credentials!", found_issues);
    }
}

fn print_hook(shell: &str) {
    match shell.to_lowercase().as_str() {
        "zsh" => print!(
            "{}",
            r#"# SecretGuard Zsh Hook
zshaddhistory() {
    emulate -L zsh
    local raw_cmd="${1%%$'\n'}"
    if [[ ${raw_cmd} =~ ^\s*$ || ${#raw_cmd} -lt 15 ]]; then
        return 0
    fi

    local sanitized
    sanitized=$(secretguard sanitize "$raw_cmd" 2>/dev/null)
    local status=$?

    if [[ $status -eq 1 ]]; then
        print -s -- "$sanitized"
        echo "\033[1;33m[secretguard]\033[0m 🚨 Secret stripped from history: \033[2m$sanitized\033[0m" >&2
        return 1
    fi
    return 0
}
"#
        ),
        "bash" => print!(
            "{}",
            r#"# SecretGuard Bash Hook
# Append to ~/.bashrc
_secretguard_bash_preexec() {
    local last_hist
    last_hist=$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    if secretguard check "$last_hist" 2>/dev/null; then
        : # clean
    else
        history -d $(history 1 | awk '{print $1}')
        echo "[secretguard] 🚨 Secret detected and removed from bash history." >&2
    fi
}
PROMPT_COMMAND="_secretguard_bash_preexec; $PROMPT_COMMAND"
"#
        ),
        "powershell" | "pwsh" => print!(
            "{}",
            r#"# SecretGuard PowerShell Hook
# Add to $PROFILE
Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
function Invoke-SecretGuard {
    param([string]$Line)
    if (secretguard check "$Line") {
        # clean
    } else {
        Write-Warning "[secretguard] 🚨 Secret intercepted!"
    }
}
"#
        ),
        _ => eprintln!("Unsupported shell: {}. Supported: zsh, bash, powershell", shell),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(2);
    }

    let subcommand = args[1].as_str();
    let engine = SecretGuardEngine::new();

    match subcommand {
        "check" => {
            let input = if args.len() >= 3 {
                args[2..].join(" ")
            } else {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer).unwrap_or(0);
                buffer
            };

            let result = engine.scan_and_sanitize(&input);
            if result.has_secret {
                eprintln!("[secretguard] Found: {:?}", result.matched_rules);
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        "sanitize" => {
            let input = if args.len() >= 3 {
                args[2..].join(" ")
            } else {
                let mut buffer = String::new();
                io::stdin().read_to_string(&mut buffer).unwrap_or(0);
                buffer
            };

            let result = engine.scan_and_sanitize(&input);
            print!("{}", result.sanitized_text);

            if result.has_secret {
                process::exit(1);
            } else {
                process::exit(0);
            }
        }
        "hook" => {
            let shell = if args.len() >= 3 { &args[2] } else { "zsh" };
            print_hook(shell);
        }
        "audit" => {
            let target = if args.len() >= 3 { Some(args[2].as_str()) } else { None };
            run_audit(target, &engine);
        }
        "clean-history" => {
            let mut dry_run = false;
            let mut target = None;
            for arg in &args[2..] {
                if arg == "--dry-run" {
                    dry_run = true;
                } else if target.is_none() {
                    target = Some(arg.as_str());
                }
            }
            run_clean_history(target, dry_run, &engine);
        }
        "protect-agent" => {
            let target = if args.len() >= 3 { Some(args[2].as_str()) } else { None };
            run_protect_agent(target, &engine);
        }
        "wrap" => {
            if args.len() < 3 {
                eprintln!("Usage: secretguard wrap <command> [args...]");
                process::exit(2);
            }

            let child_cmd = &args[2];
            let child_args = &args[3..];

            let mut child = Command::new(child_cmd)
                .args(child_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to start child process");

            if let Some(stdout) = child.stdout.take() {
                let reader = io::BufReader::new(stdout);
                let stdout_handle = io::stdout();
                let mut handle = stdout_handle.lock();

                for line in reader.lines().flatten() {
                    let res = engine.scan_and_sanitize(&line);
                    writeln!(handle, "{}", res.sanitized_text).unwrap();
                }
            }

            let status = child.wait().expect("Child process wasn't running");
            process::exit(status.code().unwrap_or(0));
        }
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}
