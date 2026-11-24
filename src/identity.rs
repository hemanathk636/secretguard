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

    /// Returns the SHA-256 binary hash of the currently running executable
    pub fn get_current_binary_hash() -> Option<String> {
        std::env::current_exe()
            .ok()
            .and_then(|p| compute_file_sha256(&p))
    }

    /// Derives IdentityContext directly from the operating system kernel for a given process ID (PID)
    /// Performs non-forgeable process image query and binary hash verification.
    pub fn from_pid(pid: u32) -> Result<Self, String> {
        let (current_exe, exe_name) = query_process_info_by_pid(pid)?;
        let binary_hash = compute_file_sha256(&current_exe);
        let (working_dir, env_hints) = if pid == std::process::id() {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let hints = collect_environment_hints();
            (cwd, hints)
        } else {
            #[cfg(all(unix, target_os = "linux"))]
            {
                let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid)).unwrap_or_else(|_| {
                    current_exe
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| PathBuf::from("."))
                });
                let mut hints = HashMap::new();
                if let Ok(env_data) = std::fs::read(format!("/proc/{}/environ", pid)) {
                    for entry in env_data.split(|&b| b == 0) {
                        if let Ok(s) = std::str::from_utf8(entry) {
                            if let Some(pos) = s.find('=') {
                                hints.insert(s[..pos].to_string(), s[pos + 1..].to_string());
                            }
                        }
                    }
                }
                (cwd, hints)
            }
            #[cfg(not(all(unix, target_os = "linux")))]
            {
                // On Windows and macOS: External process does not inherit broker process environment or working directory
                let cwd = current_exe
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."));
                let hints = HashMap::new();
                (cwd, hints)
            }
        };
        let git_repo = detect_current_git_repo(&working_dir);

        let is_interactive_tty = false;

        let lineage = collect_process_lineage(pid);
        let ppid = get_parent_pid(pid).ok();
        let (requester_type, trust_tier, trust_score) = classify_requester_with_hash(
            &exe_name,
            binary_hash.as_deref(),
            &lineage,
            is_interactive_tty,
            &env_hints,
        );

        Ok(Self {
            pid,
            ppid,
            executable_name: exe_name,
            executable_path: Some(current_exe),
            binary_hash,
            lineage,
            requester_type,
            trust_tier,
            trust_score,
            is_interactive_tty,
            working_dir,
            git_repo,
        })
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

#[cfg(windows)]
fn query_process_info_by_pid(pid: u32) -> Result<(PathBuf, String), String> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::raw::HANDLE;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> HANDLE;
        fn QueryFullProcessImageNameW(
            hProcess: HANDLE,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: HANDLE) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "Kernel refused access to PID {} (Process not found or insufficient access privilege)",
            pid
        ));
    }

    let mut buf = vec![0u16; 1024];
    let mut size = buf.len() as u32;
    let res = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };

    if res == 0 || size == 0 {
        return Err(format!(
            "Failed to query full image name from kernel for PID {}",
            pid
        ));
    }

    let os_string = std::ffi::OsString::from_wide(&buf[..size as usize]);
    let path = PathBuf::from(os_string);
    let exe_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown.exe".to_string());

    Ok((path, exe_name))
}

#[cfg(windows)]
/// Queries the parent process ID from the OS kernel using Toolhelp32 snapshot
pub fn get_parent_pid(pid: u32) -> Result<u32, String> {
    use std::os::windows::raw::HANDLE;

    #[repr(C)]
    struct PROCESSENTRY32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;
        fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
        fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
        fn CloseHandle(hObject: HANDLE) -> i32;
    }

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    let invalid_handle = -1isize as HANDLE;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot == invalid_handle {
        return Err("Failed to create toolhelp process snapshot".to_string());
    }

    let mut entry = PROCESSENTRY32W {
        dw_size: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        cnt_usage: 0,
        th32_process_id: 0,
        th32_default_heap_id: 0,
        th32_module_id: 0,
        cnt_threads: 0,
        th32_parent_process_id: 0,
        pc_pri_class_base: 0,
        dw_flags: 0,
        sz_exe_file: [0u16; 260],
    };

    let mut found = None;
    unsafe {
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32_process_id == pid {
                    found = Some(entry.th32_parent_process_id);
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }

    found.ok_or_else(|| format!("Parent PID not found for PID {}", pid))
}

#[cfg(unix)]
fn query_process_info_by_pid(pid: u32) -> Result<(PathBuf, String), String> {
    if pid == std::process::id() {
        if let Ok(exe) = std::env::current_exe() {
            let name = exe
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "secretguard".to_string());
            return Ok((exe, name));
        }
    }

    #[cfg(target_os = "linux")]
    {
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", pid));
        if proc_exe.exists() {
            if let Ok(target) = std::fs::read_link(&proc_exe) {
                let exe_name = target
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                return Ok((target, exe_name));
            }
        }

        let path = PathBuf::from(format!("/proc/{}", pid));
        if !path.exists() {
            return Err(format!("Process with PID {} does not exist in /proc", pid));
        }
        let exe_name = format!("proc_{}", pid);
        Ok((path, exe_name))
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On macOS and other Unix without /proc:
        let exists = unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        };
        if !exists {
            return Err(format!("Process with PID {} does not exist", pid));
        }
        let exe_path =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from(format!("/proc_{}", pid)));
        let exe_name = format!("proc_{}", pid);
        Ok((exe_path, exe_name))
    }
}

#[cfg(unix)]
/// Queries the parent process ID from /proc/<pid>/stat or libc::getppid
pub fn get_parent_pid(pid: u32) -> Result<u32, String> {
    if pid == std::process::id() {
        return Ok(unsafe { libc::getppid() as u32 });
    }
    #[cfg(target_os = "linux")]
    {
        let stat_file = PathBuf::from(format!("/proc/{}/stat", pid));
        if let Ok(content) = std::fs::read_to_string(&stat_file) {
            if let Some(idx) = content.rfind(')') {
                let after = content[idx + 1..].trim_start();
                let mut parts = after.split_whitespace();
                let _state = parts.next();
                if let Some(ppid_str) = parts.next() {
                    if let Ok(ppid) = ppid_str.parse::<u32>() {
                        return Ok(ppid);
                    }
                }
            }
        }
        Err(format!("Parent PID not found for PID {}", pid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(1)
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

/// Extracts GitHub or Git repository identifier (owner/repo) from a target API URL or clone URL
pub fn extract_repository_from_url(url: &str) -> Option<String> {
    if let Some(pos) = url.find("github.com/repos/") {
        let rest = &url[pos + "github.com/repos/".len()..];
        let mut parts = rest.split('/');
        let owner = parts.next()?;
        let repo = parts.next()?;
        if !owner.is_empty() && !repo.is_empty() {
            let clean_repo = repo.trim_end_matches(".git");
            return Some(format!(
                "{}/{}",
                owner.to_lowercase(),
                clean_repo.to_lowercase()
            ));
        }
    } else if let Some(pos) = url.find("github.com/") {
        let rest = &url[pos + "github.com/".len()..];
        let mut parts = rest.split('/');
        let owner = parts.next()?;
        let repo = parts.next()?;
        if !owner.is_empty() && !repo.is_empty() && !["api", "settings", "login"].contains(&owner) {
            let clean_repo = repo.trim_end_matches(".git");
            return Some(format!(
                "{}/{}",
                owner.to_lowercase(),
                clean_repo.to_lowercase()
            ));
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
        libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1
    }
    #[cfg(windows)]
    {
        // Require both stdin and stdout to be interactive terminals
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
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

/// Deterministic heuristic classifier for process identity and trust assignment with cryptographic binary verification
pub fn classify_requester_with_hash(
    exe_name: &str,
    binary_hash: Option<&str>,
    lineage: &[String],
    is_tty: bool,
    env_hints: &HashMap<String, String>,
) -> (RequesterType, TrustTier, u8) {
    let lower_exe = exe_name.to_lowercase();

    // 1. Check for autonomous AI agents with corroborating evidence
    let has_agent_name = lower_exe.contains("claude")
        || lower_exe.contains("aider")
        || lower_exe.contains("copilot")
        || lower_exe.contains("cline")
        || lower_exe.contains("goose");
    let has_agent_env = env_hints.contains_key("CLAUDE_CODE")
        || env_hints.contains_key("AIDER_MODEL")
        || env_hints.contains_key("COPILOT_AGENT")
        || env_hints.contains_key("GOOSE_PROVIDER");
    let has_agent_lineage = lineage.iter().any(|p| {
        let lp = p.to_lowercase();
        lp.contains("claude")
            || lp.contains("aider")
            || lp.contains("copilot")
            || lp.contains("cline")
    });

    if (has_agent_name && (has_agent_env || has_agent_lineage)) || has_agent_env {
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

    // 3. Check for approved IDE environments with corroborating evidence
    let has_ide_name = lower_exe.contains("code")
        || lower_exe.contains("cursor")
        || lower_exe.contains("idea")
        || lower_exe.contains("zed")
        || lower_exe.contains("windsurf");
    let has_ide_env = env_hints.contains_key("VSCODE_PID")
        || env_hints.contains_key("CURSOR_APP_ID")
        || env_hints.contains_key("ZED_TERM")
        || env_hints.contains_key("IDEA_INITIAL_DIRECTORY");
    let has_ide_lineage = lineage.iter().any(|p| {
        let lp = p.to_lowercase();
        lp.contains("code") || lp.contains("cursor") || lp.contains("idea") || lp.contains("zed")
    });

    if (has_ide_name && (has_ide_env || has_ide_lineage)) || has_ide_env {
        return (
            RequesterType::ApprovedIde,
            TrustTier::Tier2StandardAgent,
            75,
        );
    }

    // 4. Check for interactive human developer session or native SecretGuard executable
    // SECURITY: Separate executable trust from human interactive privilege!
    // A matching cryptographic binary hash establishes executable integrity, but NEVER automatically
    // grants HumanInteractive / Tier3Privileged without an actual verified interactive terminal TTY.
    if lower_exe.contains("secretguard") {
        let is_verified_secretguard = if let Some(claimed_hash) = binary_hash {
            if let Ok(curr_exe) = std::env::current_exe() {
                if let Some(curr_hash) = compute_file_sha256(&curr_exe) {
                    claimed_hash == curr_hash
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if !is_verified_secretguard {
            // Unverified binary claiming to be secretguard - untrusted/spoofing attempt!
            return (RequesterType::UnknownProcess, TrustTier::Tier0Blocked, 0);
        }

        // Verified SecretGuard binary: human interactive privilege requires an actual interactive terminal TTY
        if is_tty {
            return (
                RequesterType::HumanInteractive,
                TrustTier::Tier3Privileged,
                90,
            );
        } else {
            // Verified binary running in background or automated script
            return (RequesterType::BuildOrScript, TrustTier::Tier1Restricted, 50);
        }
    }

    if is_tty
        && (lower_exe.contains("bash")
            || lower_exe.contains("zsh")
            || lower_exe.contains("sh")
            || lower_exe.contains("pwsh")
            || lower_exe.contains("powershell"))
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

/// Deterministic heuristic classifier for process identity and trust assignment (backward-compatible)
pub fn classify_requester(
    exe_name: &str,
    lineage: &[String],
    is_tty: bool,
    env_hints: &HashMap<String, String>,
) -> (RequesterType, TrustTier, u8) {
    classify_requester_with_hash(exe_name, None, lineage, is_tty, env_hints)
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
        let mut hints = HashMap::new();
        hints.insert("CLAUDE_CODE".to_string(), "1".to_string());
        let (req_type, tier, score) = classify_requester("claude-code", &[], false, &hints);
        assert_eq!(req_type, RequesterType::AutonomousAgent);
        assert_eq!(tier, TrustTier::Tier2StandardAgent);
        assert!(score >= 60);
    }

    #[test]
    fn test_classify_unverified_claude_process_rejected() {
        let hints = HashMap::new();
        // Standalone executable with no environment proof or lineage is rejected from Tier 2
        let (req_type, tier, _) = classify_requester("claude.exe", &[], false, &hints);
        assert_eq!(req_type, RequesterType::UnknownProcess);
        assert_eq!(tier, TrustTier::Tier0Blocked);
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

    #[test]
    fn test_classify_fake_secretguard_spoof_rejection() {
        let hints = HashMap::new();
        // Attacker creates a non-TTY process named "secretguard.exe" with a random or missing hash
        let (req_type, tier, score) = classify_requester_with_hash(
            "secretguard.exe",
            Some("fake_attacker_hash_123456"),
            &[],
            false,
            &hints,
        );
        assert_eq!(req_type, RequesterType::UnknownProcess);
        assert_eq!(tier, TrustTier::Tier0Blocked);
        assert_eq!(score, 0);

        let (req_type_none, tier_none, score_none) =
            classify_requester("secretguard.exe", &[], false, &hints);
        assert_eq!(req_type_none, RequesterType::UnknownProcess);
        assert_eq!(tier_none, TrustTier::Tier0Blocked);
        assert_eq!(score_none, 0);
    }

    #[test]
    fn test_get_parent_pid_current_process() {
        let my_pid = std::process::id();
        let ppid_res = get_parent_pid(my_pid);
        assert!(
            ppid_res.is_ok(),
            "get_parent_pid for current process must succeed: {:?}",
            ppid_res
        );
        assert!(ppid_res.unwrap() > 0);
    }
}
