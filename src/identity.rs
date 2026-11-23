//! Identity & Trust Engine for SecretGuard
//! Inspects calling processes, analyzes lineage, classifies requesters, and assigns trust scores.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Classification of the calling process entity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequesterType {
    /// Human developer interacting directly via interactive terminal/TTY
    HumanInteractive,
    /// Verified IDE environment (VS Code, Cursor, IntelliJ, Zed, Windsurf)
    ApprovedIde,
    /// Autonomous AI coding assistant (Claude Code, Aider, Copilot, Cline, Goose)
    AutonomousAgent,
    /// Model Context Protocol (MCP) server or tool worker
    McpServer,
    /// Automated build tool, package manager, or script execution
    BuildOrScript,
    /// Unidentified, unverified, or third-party background process
    UnknownProcess,
}

/// Security trust tiers determining allowed authorization scopes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustTier {
    /// Score 0-19: Untrusted or flagged process; all credential access blocked
    Tier0Blocked,
    /// Score 20-49: Restricted execution; read-only delegated operations only
    Tier1Restricted,
    /// Score 50-79: Standard AI agent; delegated execution under policy rules
    Tier2StandardAgent,
    /// Score 80-100: Human developer or verified interactive console; full policy scope
    Tier3Privileged,
}

/// Rich identity and trust context for a requesting process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub executable_name: String,
    pub executable_path: Option<PathBuf>,
    pub binary_hash: Option<String>,
    pub lineage: Vec<String>,
    pub requester_type: RequesterType,
    pub trust_tier: TrustTier,
    pub trust_score: u8,
    pub is_interactive_tty: bool,
    pub working_dir: PathBuf,
    pub git_repo: Option<String>,
}

impl IdentityContext {
    /// Inspects the calling process and derives its IdentityContext
    pub fn current() -> Self {
        let pid = std::process::id();
        let current_exe = std::env::current_exe().ok();
        let exe_name = current_exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let binary_hash = current_exe.as_ref().and_then(|p| compute_file_sha256(p));
        let working_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let git_repo = detect_current_git_repo(&working_dir);

        let env_hints = collect_environment_hints();
        let is_interactive_tty = is_terminal_interactive();

        let lineage = collect_process_lineage(pid);
        let (requester_type, trust_tier, trust_score) =
            classify_requester(&exe_name, &lineage, is_interactive_tty, &env_hints);

        Self {
            pid,
            ppid: lineage.first().and_then(|s| s.parse::<u32>().ok()),
            executable_name: exe_name,
            executable_path: current_exe,
            binary_hash,
            lineage,
            requester_type,
            trust_tier,
            trust_score,
            is_interactive_tty,
            working_dir,
            git_repo,
        }
    }

    /// Creates a mock identity context for policy testing and audit simulations
    pub fn mock(
        name: &str,
        requester_type: RequesterType,
        repo: Option<&str>,
        working_dir: Option<PathBuf>,
    ) -> Self {
        let (trust_tier, trust_score) = match requester_type {
            RequesterType::HumanInteractive => (TrustTier::Tier3Privileged, 95),
            RequesterType::ApprovedIde => (TrustTier::Tier2StandardAgent, 75),
            RequesterType::AutonomousAgent => (TrustTier::Tier2StandardAgent, 65),
            RequesterType::McpServer => (TrustTier::Tier1Restricted, 45),
            RequesterType::BuildOrScript => (TrustTier::Tier1Restricted, 35),
            RequesterType::UnknownProcess => (TrustTier::Tier0Blocked, 10),
        };

        Self {
            pid: 1337,
            ppid: Some(1),
            executable_name: name.to_string(),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{}", name))),
            binary_hash: Some("mock_binary_hash_0123456789abcdef".to_string()),
            lineage: vec!["init".to_string()],
            requester_type,
            trust_tier,
            trust_score,
            is_interactive_tty: requester_type == RequesterType::HumanInteractive,
            working_dir: working_dir.unwrap_or_else(|| PathBuf::from("/workspace")),
            git_repo: repo.map(|r| r.to_string()),
        }
    }
}

/// Computes SHA-256 hash of an executable binary
pub fn compute_file_sha256(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Detects git repository name from working directory or ancestors
pub fn detect_current_git_repo(start_dir: &Path) -> Option<String> {
    let mut curr = start_dir.to_path_buf();
    loop {
        let git_dir = curr.join(".git");
        if git_dir.exists() {
            let config_path = git_dir.join("config");
            if config_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("url = ") {
                            let url = trimmed.trim_start_matches("url = ").trim();
                            // Extract owner/repo from https://github.com/owner/repo.git or git@github.com:owner/repo.git
                            return Some(clean_git_repo_identifier(url));
                        }
                    }
                }
            }
            // Fallback to directory name
            return curr.file_name().map(|s| s.to_string_lossy().to_string());
        }
        if !curr.pop() {
            break;
        }
    }
    None
}

/// Normalizes git repo URLs into clean "owner/repo" format
pub fn clean_git_repo_identifier(raw_url: &str) -> String {
    let stripped = raw_url.trim_end_matches('/').trim_end_matches(".git");
    if let Some(idx) = stripped.rfind('/') {
        if let Some(second_idx) = stripped[..idx].rfind('/') {
            return stripped[second_idx + 1..].to_string();
        } else if let Some(colon_idx) = stripped[..idx].rfind(':') {
            return stripped[colon_idx + 1..].to_string();
        }
    }
    stripped.to_string()
}

/// Checks if stdout/stdin is an interactive terminal
fn is_terminal_interactive() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(libc::STDIN_FILENO) == 1
    }
    #[cfg(windows)]
    {
        // Safe heuristic checking stdin handle
        use std::io::IsTerminal;
        std::io::stdin().is_terminal()
    }
}

/// Collects process tree names where supported
fn collect_process_lineage(_pid: u32) -> Vec<String> {
    let mut lineage = Vec::new();
    if let Ok(parent_var) = std::env::var("SECRETGUARD_CALLER_LINEAGE") {
        for part in parent_var.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                lineage.push(trimmed.to_string());
            }
        }
    }
    lineage
}

/// Collects environment variables that provide caller hints
fn collect_environment_hints() -> HashMap<String, String> {
    let mut hints = HashMap::new();
    let target_vars = [
        "TERM_PROGRAM",
        "VSCODE_PID",
        "CURSOR_APP_ID",
        "CLAUDE_CODE",
        "AIDER_MODEL",
        "MCP_SERVER_NAME",
        "CI",
        "GITHUB_ACTIONS",
    ];
    for var in target_vars {
        if let Ok(val) = std::env::var(var) {
            hints.insert(var.to_string(), val);
        }
    }
    hints
}

/// Deterministic heuristic classifier for process identity and trust assignment
pub fn classify_requester(
    exe_name: &str,
    lineage: &[String],
    is_tty: bool,
    env_hints: &HashMap<String, String>,
) -> (RequesterType, TrustTier, u8) {
    let lower_exe = exe_name.to_lowercase();

    // 1. Check for autonomous AI agents
    if lower_exe.contains("claude")
        || lower_exe.contains("aider")
        || lower_exe.contains("copilot")
        || lower_exe.contains("cline")
        || lower_exe.contains("goose")
        || env_hints.contains_key("CLAUDE_CODE")
        || env_hints.contains_key("AIDER_MODEL")
    {
        return (
            RequesterType::AutonomousAgent,
            TrustTier::Tier2StandardAgent,
            65,
        );
    }

    // 2. Check for MCP server processes
    if lower_exe.contains("mcp")
        || env_hints.contains_key("MCP_SERVER_NAME")
        || lineage.iter().any(|p| p.to_lowercase().contains("mcp"))
    {
        return (RequesterType::McpServer, TrustTier::Tier1Restricted, 45);
    }

    // 3. Check for approved IDE environments
    if lower_exe.contains("code")
        || lower_exe.contains("cursor")
        || lower_exe.contains("idea")
        || lower_exe.contains("zed")
        || lower_exe.contains("windsurf")
        || env_hints.contains_key("VSCODE_PID")
        || env_hints.contains_key("CURSOR_APP_ID")
    {
        return (
            RequesterType::ApprovedIde,
            TrustTier::Tier2StandardAgent,
            75,
        );
    }

    // 4. Check for interactive human developer session
    if is_tty
        && (lower_exe.contains("bash")
            || lower_exe.contains("zsh")
            || lower_exe.contains("sh")
            || lower_exe.contains("pwsh")
            || lower_exe.contains("powershell")
            || lower_exe.contains("secretguard"))
    {
        return (
            RequesterType::HumanInteractive,
            TrustTier::Tier3Privileged,
            90,
        );
    }

    // 5. Automated build systems or scripts
    if env_hints.contains_key("CI")
        || env_hints.contains_key("GITHUB_ACTIONS")
        || lower_exe.contains("cargo")
        || lower_exe.contains("npm")
        || lower_exe.contains("pnpm")
        || lower_exe.contains("python")
    {
        return (RequesterType::BuildOrScript, TrustTier::Tier1Restricted, 40);
    }

    // 6. Unknown process
    (RequesterType::UnknownProcess, TrustTier::Tier0Blocked, 15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_git_repo_identifier() {
        assert_eq!(
            clean_git_repo_identifier("https://github.com/hemanathk636/secretguard.git"),
            "hemanathk636/secretguard"
        );
        assert_eq!(
            clean_git_repo_identifier("git@github.com:org/repo.git"),
            "org/repo"
        );
    }

    #[test]
    fn test_classify_ai_agent() {
        let hints = HashMap::new();
        let (req_type, tier, score) = classify_requester("claude-code", &[], false, &hints);
        assert_eq!(req_type, RequesterType::AutonomousAgent);
        assert_eq!(tier, TrustTier::Tier2StandardAgent);
        assert!(score >= 60);
    }

    #[test]
    fn test_classify_mcp_server() {
        let mut hints = HashMap::new();
        hints.insert("MCP_SERVER_NAME".to_string(), "filesystem".to_string());
        let (req_type, tier, score) = classify_requester("node", &[], false, &hints);
        assert_eq!(req_type, RequesterType::McpServer);
        assert_eq!(tier, TrustTier::Tier1Restricted);
        assert_eq!(score, 45);
    }

    #[test]
    fn test_classify_unknown_process() {
        let hints = HashMap::new();
        let (req_type, tier, _) = classify_requester("random_binary_123", &[], false, &hints);
        assert_eq!(req_type, RequesterType::UnknownProcess);
        assert_eq!(tier, TrustTier::Tier0Blocked);
    }
}
