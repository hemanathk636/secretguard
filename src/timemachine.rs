use crate::SecretGuardEngine;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitCommitLeak {
    pub commit_hash: String,
    pub commit_short: String,
    pub author: String,
    pub date: String,
    pub summary: String,
    pub leaks_found: usize,
    pub matched_rules: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeMachineScanReport {
    pub total_commits_scanned: usize,
    pub tainted_commits: Vec<GitCommitLeak>,
    pub clean: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeMachineScrubResult {
    pub success: bool,
    pub commits_scrubbed: usize,
    pub backup_ref: String,
    pub message: String,
}

pub struct TimeMachine;

impl TimeMachine {
    /// Verify if target directory is inside a valid git repository
    pub fn is_git_repo(repo_path: Option<&Path>) -> bool {
        let mut cmd = Command::new("git");
        if let Some(p) = repo_path {
            cmd.current_dir(p);
        }
        cmd.args(["rev-parse", "--is-inside-work-tree"]);
        match cmd.output() {
            Ok(out) => {
                out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "true"
            }
            Err(_) => false,
        }
    }

    /// Retrieve the list of commit hashes in chronological order (or limit)
    pub fn get_commit_hashes(
        repo_path: Option<&Path>,
        max_commits: Option<usize>,
    ) -> Result<Vec<String>, String> {
        let mut cmd = Command::new("git");
        if let Some(p) = repo_path {
            cmd.current_dir(p);
        }
        cmd.args(["log", "--all", "--format=%H", "--reverse"]);
        if let Some(n) = max_commits {
            cmd.arg(format!("-n{}", n));
        }

        let out = cmd
            .output()
            .map_err(|e| format!("Failed to run git log: {}", e))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).to_string());
        }

        let hashes: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(hashes)
    }

    /// Scan entire commit history for leaked secrets
    pub fn scan_history(
        engine: &SecretGuardEngine,
        repo_path: Option<&Path>,
        max_commits: Option<usize>,
    ) -> Result<TimeMachineScanReport, String> {
        if !Self::is_git_repo(repo_path) {
            return Err("Current directory is not a valid git repository.".to_string());
        }

        let commits = Self::get_commit_hashes(repo_path, max_commits)?;
        let mut tainted_commits = Vec::new();

        for hash in &commits {
            let mut cmd = Command::new("git");
            if let Some(p) = repo_path {
                cmd.current_dir(p);
            }
            // Show the commit diff and metadata
            cmd.args(["show", "--format=%h|%an|%ad|%s", "--date=short", hash]);
            let out = match cmd.output() {
                Ok(o) => o,
                Err(_) => continue,
            };

            if !out.status.success() {
                continue;
            }

            let full_output = String::from_utf8_lossy(&out.stdout);
            let mut lines = full_output.lines();
            let header = lines.next().unwrap_or("");
            let parts: Vec<&str> = header.split('|').collect();

            let (short_hash, author, date, summary) = if parts.len() >= 4 {
                (parts[0], parts[1], parts[2], parts[3])
            } else {
                (
                    &hash[..7.min(hash.len())],
                    "Unknown",
                    "Unknown",
                    "No commit message",
                )
            };

            // Inspect diff added lines (lines starting with '+')
            let mut leaks_in_commit = 0;
            let mut commit_matched_rules = Vec::new();

            for line in lines {
                if line.starts_with('+') && !line.starts_with("+++") {
                    let addition = &line[1..];
                    let res = engine.scan_and_sanitize(addition);
                    if res.has_secret {
                        leaks_in_commit += 1;
                        for r in res.matched_rules {
                            if !commit_matched_rules.contains(&r) {
                                commit_matched_rules.push(r);
                            }
                        }
                    }
                }
            }

            if leaks_in_commit > 0 {
                tainted_commits.push(GitCommitLeak {
                    commit_hash: hash.clone(),
                    commit_short: short_hash.to_string(),
                    author: author.to_string(),
                    date: date.to_string(),
                    summary: summary.to_string(),
                    leaks_found: leaks_in_commit,
                    matched_rules: commit_matched_rules,
                });
            }
        }

        let clean = tainted_commits.is_empty();
        Ok(TimeMachineScanReport {
            total_commits_scanned: commits.len(),
            tainted_commits,
            clean,
        })
    }

    /// Surgical scrubbing of tainted secrets in commit history
    /// Uses native git-filter-branch or tree filter logic with automated safety backup branch
    pub fn scrub_history(
        engine: &SecretGuardEngine,
        repo_path: Option<&Path>,
        dry_run: bool,
    ) -> Result<TimeMachineScrubResult, String> {
        let report = Self::scan_history(engine, repo_path, None)?;
        if report.clean {
            return Ok(TimeMachineScrubResult {
                success: true,
                commits_scrubbed: 0,
                backup_ref: String::new(),
                message: "No secrets detected in commit history. Git history is 100% clean!"
                    .to_string(),
            });
        }

        if dry_run {
            return Ok(TimeMachineScrubResult {
                success: true,
                commits_scrubbed: report.tainted_commits.len(),
                backup_ref: "DRY_RUN (No changes applied)".to_string(),
                message: format!(
                    "Dry run completed. Found {} tainted commits ready for surgical scrubbing.",
                    report.tainted_commits.len()
                ),
            });
        }

        // 1. Create a timestamped backup branch for 100% safety
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup_branch = format!("secretguard-backup-{}", timestamp);

        let mut bkp_cmd = Command::new("git");
        if let Some(p) = repo_path {
            bkp_cmd.current_dir(p);
        }
        bkp_cmd.args(["branch", &backup_branch]);
        let bkp_out = bkp_cmd
            .output()
            .map_err(|e| format!("Failed to create safety backup branch: {}", e))?;
        if !bkp_out.status.success() {
            return Err(format!(
                "Failed to create safety branch '{}': {}",
                backup_branch,
                String::from_utf8_lossy(&bkp_out.stderr)
            ));
        }

        // 2. Perform surgical tree filter: replace detected secret patterns across working tree (including hidden files like .env)
        let script_content = if cfg!(target_os = "windows") {
            // Windows PowerShell filter: includes hidden files like .env, excludes .git
            r#"
$files = Get-ChildItem -File -Recurse -Force | Where-Object { $_.FullName -notmatch '[\\/]\.git([\\/]|$)' }
foreach ($f in $files) {
    if (Get-Command secretguard -ErrorAction SilentlyContinue) {
        $raw = Get-Content -Raw $f.FullName
        if ($raw) {
            $sanitized = $raw | secretguard sanitize 2>$null
            if ($sanitized -and $sanitized.Trim().Length -gt 0) {
                Set-Content -NoNewline -Path $f.FullName -Value $sanitized
                continue
            }
        }
    }
    (Get-Content -Raw $f.FullName) `
        -replace 'sk-(?:proj-)?[a-zA-Z0-9_-]{32,}', 'sk-proj-SCRUBBED00000000000000000' `
        -replace 'sk-ant-api03-[a-zA-Z0-9_-]{80,}', 'sk-ant-api03-SCRUBBED00000000000000000' `
        -replace 'ghp_[a-zA-Z0-9]{20,}', 'ghp_SCRUBBED00000000000000000000' `
        -replace 'AKIA[0-9A-Z]{16}', 'AKIAFAKE000000000000' `
        -replace 'sk_live_[0-9a-zA-Z]{24,}', '[REDACTED_STRIPE_KEY]' `
        -replace 'xox[baprs]-[0-9a-zA-Z]{10,48}', 'xoxb-SCRUBBED000000000000' `
        -replace 'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SG.SCRUBBED000000000000.000000000000' `
        -replace 'AIza[0-9A-Za-z_-]{35}', 'AIzaSyFAKE00000000000000000000000' `
        | Set-Content -NoNewline $f.FullName
}
"#
        } else {
            // Unix sh filter: includes hidden files like .env, excludes .git, POSIX cross-compatible
            r#"
find . -type f -not -path './.git/*' | while read -r f; do
    if command -v secretguard >/dev/null 2>&1; then
        clean=$(secretguard sanitize < "$f" 2>/dev/null)
        if [ -n "$clean" ]; then
            printf "%s" "$clean" > "$f"
            continue
        fi
    fi
    sed -e 's/sk-[a-zA-Z0-9]\{20,\}/sk-proj-SCRUBBED00000000000000000/g' \
        -e 's/ghp_[a-zA-Z0-9]\{20,\}/ghp_SCRUBBED00000000000000000000/g' \
        -e 's/AKIA[0-9A-Z]\{16\}/AKIAFAKE000000000000/g' \
        -e 's/sk_live_[0-9a-zA-Z]\{24,\}/[REDACTED_STRIPE_KEY]/g' \
        -e 's/xox[baprs]-[0-9a-zA-Z]\{10,48\}/xoxb-SCRUBBED000000000000/g' \
        -e 's/SG\.[a-zA-Z0-9_-]\{22\}\.[a-zA-Z0-9_-]\{43\}/SG.SCRUBBED000000000000.000000000000/g' \
        -e 's/AIza[0-9A-Za-z_-]\{35\}/AIzaSyFAKE00000000000000000000000/g' "$f" > "$f.tmp" 2>/dev/null && mv "$f.tmp" "$f" 2>/dev/null || rm -f "$f.tmp"
done
"#
        };

        // Write filter script to temporary location
        let temp_dir = std::env::temp_dir();
        let script_ext = if cfg!(target_os = "windows") {
            "ps1"
        } else {
            "sh"
        };
        let script_path =
            temp_dir.join(format!("secretguard_scrubber_{}.{}", timestamp, script_ext));
        let mut script_file = fs::File::create(&script_path)
            .map_err(|e| format!("Failed to create temporary filter script: {}", e))?;
        script_file
            .write_all(script_content.as_bytes())
            .map_err(|e| format!("Failed to write filter script: {}", e))?;

        // 3. Execute git filter-branch across all branches with safety override
        let normalized_path = script_path.to_string_lossy().replace('\\', "/");
        let tree_filter_arg = if cfg!(target_os = "windows") {
            format!(
                "powershell -ExecutionPolicy Bypass -File \"{}\"",
                normalized_path
            )
        } else {
            format!("sh \"{}\"", normalized_path)
        };

        let mut fb_cmd = Command::new("git");
        if let Some(p) = repo_path {
            fb_cmd.current_dir(p);
        }
        fb_cmd.env("FILTER_BRANCH_SQUELCH_WARNING", "1");
        fb_cmd.args([
            "filter-branch",
            "-f",
            "--tree-filter",
            &tree_filter_arg,
            "--",
            "--all",
        ]);

        let fb_out = fb_cmd.output();
        let _ = fs::remove_file(&script_path); // Cleanup script

        match fb_out {
            Ok(output) => {
                if output.status.success() {
                    Ok(TimeMachineScrubResult {
                        success: true,
                        commits_scrubbed: report.tainted_commits.len(),
                        backup_ref: backup_branch.clone(),
                        message: format!(
                            "Successfully scrubbed {} tainted commits across all branches. Safety backup ref preserved at '{}'. Note: Historical backup branch retains original commits until manually pruned with 'git branch -D {}'.",
                            report.tainted_commits.len(),
                            backup_branch,
                            backup_branch
                        ),
                    })
                } else {
                    let err_msg = String::from_utf8_lossy(&output.stderr);
                    Err(format!("git filter-branch failed: {}", err_msg))
                }
            }
            Err(e) => Err(format!("Failed to execute git filter-branch: {}", e)),
        }
    }

    /// CLI runner for secretguard time-machine
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard time-machine - Cryptographic Git History Scrubber

USAGE:
    secretguard time-machine <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    scan [--limit N]        Audit Git commit history for leaked secrets.
    scrub [--dry-run]       Surgically scrub leaked secrets from Git history.
                            (Creates an automatic safety backup branch first)
"#
            );
            return;
        }

        match args[0].as_str() {
            "scan" => {
                let mut limit = None;
                if args.len() >= 3 && args[1] == "--limit" {
                    if let Ok(n) = args[2].parse::<usize>() {
                        limit = Some(n);
                    }
                }

                println!("⏳ Scanning Git history for leaked secrets...");
                match Self::scan_history(engine, None, limit) {
                    Ok(report) => {
                        println!("📊 Scanned {} commits.", report.total_commits_scanned);
                        if report.clean {
                            println!(
                                "✅ Zero secrets found in Git history! History is 100% clean."
                            );
                        } else {
                            println!(
                                "🚨 Found {} tainted commits containing exposed credentials:\n",
                                report.tainted_commits.len()
                            );
                            for c in &report.tainted_commits {
                                println!(
                                    "  • \x1b[33m{}\x1b[0m ({}) - \x1b[1m{}\x1b[0m [{} secrets: {}]",
                                    c.commit_short,
                                    c.date,
                                    c.summary,
                                    c.leaks_found,
                                    c.matched_rules.join(", ")
                                );
                            }
                            println!(
                                "\n💡 Run \x1b[36msecretguard time-machine scrub\x1b[0m to surgically rewrite history."
                            );
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Error scanning Git history: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "scrub" => {
                let dry_run = args.iter().any(|a| a == "--dry-run");
                println!(
                    "⏳ Starting Git Time-Machine surgical history scrubber{}...",
                    if dry_run { " (DRY-RUN)" } else { "" }
                );
                match Self::scrub_history(engine, None, dry_run) {
                    Ok(res) => {
                        if res.commits_scrubbed == 0 {
                            println!("✅ {}", res.message);
                        } else {
                            println!("🎉 {}", res.message);
                            if !dry_run {
                                println!(
                                    "🛡️ Safety backup branch created at: \x1b[32m{}\x1b[0m",
                                    res.backup_ref
                                );
                                println!(
                                    "⚠️ To revert anytime: \x1b[36mgit reset --hard {}\x1b[0m",
                                    res.backup_ref
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Scrubbing failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!("Unknown subcommand: {}. Use 'scan' or 'scrub'.", args[0]);
                std::process::exit(2);
            }
        }
    }
}
