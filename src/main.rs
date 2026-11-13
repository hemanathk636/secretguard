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
