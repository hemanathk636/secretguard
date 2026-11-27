use secretguard::scanner::{
    install_or_upgrade_pre_commit_hook, parse_git_diff_raw_z, scan_staged_blobs_in_dir,
    scan_staged_blobs_in_dir_with_limit, HookInstallOutcome, DEFAULT_MAX_STAGED_BLOB_SIZE,
    PRE_COMMIT_HOOK_SCRIPT,
};
use secretguard::SecretGuardEngine;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn synthetic_key() -> String {
    ["sk-ant-", "api03-", "abcdef1234567890", "abcdef1234567890"].concat()
}

struct TempRepo {
    dir: PathBuf,
}

impl TempRepo {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sg_hook_test_{}_{}_{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create temp repo dir");
        let repo = Self { dir };
        repo.git_ok(&["init"]);
        repo.git_ok(&["config", "user.name", "SecretGuard Test"]);
        repo.git_ok(&["config", "user.email", "test@secretguard.dev"]);
        repo.install_hook();
        repo
    }

    fn install_hook(&self) {
        let hook_path = self.dir.join(".git").join("hooks").join("pre-commit");
        fs::write(&hook_path, PRE_COMMIT_HOOK_SCRIPT).expect("write pre-commit hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms).unwrap();
        }
    }

    fn git_ok(&self, args: &[&str]) -> Output {
        let out = Command::new("git")
            .current_dir(&self.dir)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn git_with_path(&self, args: &[&str], path_env: &std::ffi::OsStr) -> Output {
        Command::new("git")
            .current_dir(&self.dir)
            .env("PATH", path_env)
            .args(args)
            .output()
            .expect("run git with custom PATH")
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn path_with_test_binary() -> std::ffi::OsString {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_secretguard"));
    let bin_dir = bin.parent().expect("binary parent dir").to_path_buf();
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir];
    paths.extend(std::env::split_paths(&existing));
    std::env::join_paths(paths).expect("join PATH")
}

fn path_without_secretguard(extra_dir: Option<&Path>) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Some(dir) = extra_dir {
        paths.push(dir.to_path_buf());
    }
    for p in std::env::split_paths(&existing) {
        let has_sg = p.join("secretguard").exists() || p.join("secretguard.exe").exists();
        if !has_sg {
            paths.push(p);
        }
    }
    std::env::join_paths(paths).expect("join PATH without secretguard")
}

#[test]
fn test_precommit_a_newly_added_synthetic_key_blocked() {
    let repo = TempRepo::new("a_new_key");
    let key = synthetic_key();
    fs::write(repo.dir.join("config.txt"), format!("TOKEN={}\n", key)).unwrap();
    repo.git_ok(&["add", "config.txt"]);

    let out = repo.git_with_path(&["commit", "-m", "add secret"], &path_with_test_binary());
    assert!(
        !out.status.success(),
        "commit with new secret must be blocked"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[SecretGuard] Git commit blocked"),
        "expected SecretGuard block message, got: {}",
        stderr
    );
    assert!(
        !stderr.contains(&key),
        "hook output must not expose the detected secret value"
    );
}

#[test]
fn test_precommit_b_deleted_historical_synthetic_key_only_allowed() {
    let repo = TempRepo::new("b_delete_only");
    let key = synthetic_key();
    fs::write(repo.dir.join("old.txt"), format!("TOKEN={}\n", key)).unwrap();
    repo.git_ok(&["add", "old.txt"]);
    repo.git_ok(&["commit", "--no-verify", "-m", "historical commit"]);

    // Delete the key line and stage
    fs::write(repo.dir.join("old.txt"), "TOKEN=redacted\n").unwrap();
    repo.git_ok(&["add", "old.txt"]);

    let out = repo.git_with_path(&["commit", "-m", "remove key"], &path_with_test_binary());
    assert!(
        out.status.success(),
        "deleting historical synthetic key must be allowed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_precommit_c_secret_on_unchanged_line_in_modified_file_detected() {
    let repo = TempRepo::new("c_unchanged_line");
    let key = synthetic_key();
    fs::write(
        repo.dir.join("service.txt"),
        format!("SECRET={}\nVERSION=1\n", key),
    )
    .unwrap();
    repo.git_ok(&["add", "service.txt"]);
    repo.git_ok(&["commit", "--no-verify", "-m", "baseline"]);

    // Modify only line 2; line 1 remains unchanged
    fs::write(
        repo.dir.join("service.txt"),
        format!("SECRET={}\nVERSION=2\n", key),
    )
    .unwrap();
    repo.git_ok(&["add", "service.txt"]);

    let out = repo.git_with_path(&["commit", "-m", "bump version"], &path_with_test_binary());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("[SecretGuard] Git commit blocked"),
        "secret on unchanged line in modified staged file must be detected, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_d_secret_only_in_unstaged_changes_not_attributed() {
    let repo = TempRepo::new("d_unstaged_only");
    fs::write(repo.dir.join("app.txt"), "APP_MODE=safe\n").unwrap();
    repo.git_ok(&["add", "app.txt"]);

    // Write secret only to working tree without staging
    fs::write(
        repo.dir.join("app.txt"),
        format!("APP_MODE=safe\nLEAK={}\n", synthetic_key()),
    )
    .unwrap();

    let out = repo.git_with_path(&["commit", "-m", "clean staged"], &path_with_test_binary());
    assert!(
        out.status.success(),
        "unstaged secret must not block staged clean commit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_precommit_e_secretguard_missing_blocked() {
    let repo = TempRepo::new("e_missing_sg");
    fs::write(repo.dir.join("clean.txt"), "hello world\n").unwrap();
    repo.git_ok(&["add", "clean.txt"]);

    let out = repo.git_with_path(&["commit", "-m", "clean"], &path_without_secretguard(None));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("not found in PATH"),
        "commit must be blocked fail-closed when secretguard is missing, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_f_git_index_read_failure_blocked() {
    let repo = TempRepo::new("f_index_failure");
    fs::write(repo.dir.join("clean.txt"), "hello world\n").unwrap();
    repo.git_ok(&["add", "clean.txt"]);

    let engine = SecretGuardEngine::new();
    // Corrupt GIT_INDEX_FILE must cause scan_staged_blobs_in_dir to fail closed
    let bad_index = repo.dir.join("nonexistent_corrupt_index");
    fs::write(&bad_index, b"NOT_A_VALID_GIT_INDEX").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_secretguard"))
        .current_dir(&repo.dir)
        .env("GIT_INDEX_FILE", &bad_index)
        .arg("check-staged")
        .output()
        .expect("run secretguard check-staged");
    assert!(
        !out.status.success(),
        "corrupt GIT_INDEX_FILE must fail closed"
    );
    drop(engine);
}

#[test]
fn test_precommit_g_filename_with_spaces_handled() {
    let repo = TempRepo::new("g_spaces");
    let spaced_bad = "my secret file (v1).txt";
    fs::write(
        repo.dir.join(spaced_bad),
        format!("KEY={}\n", synthetic_key()),
    )
    .unwrap();
    repo.git_ok(&["add", spaced_bad]);

    let blocked = repo.git_with_path(&["commit", "-m", "spaced bad"], &path_with_test_binary());
    let blocked_stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        !blocked.status.success() && blocked_stderr.contains("[SecretGuard] Git commit blocked"),
        "secret in filename with spaces must be blocked by SecretGuard, got: {}",
        blocked_stderr
    );

    repo.git_ok(&["rm", "--cached", "-q", "--", spaced_bad]);
    fs::remove_file(repo.dir.join(spaced_bad)).unwrap();

    let spaced_clean = "my clean file (v1).txt";
    fs::write(repo.dir.join(spaced_clean), "clean content\n").unwrap();
    repo.git_ok(&["add", spaced_clean]);
    let allowed = repo.git_with_path(&["commit", "-m", "spaced clean"], &path_with_test_binary());
    assert!(
        allowed.status.success(),
        "clean filename with spaces must be allowed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
}

#[test]
fn test_precommit_h_partially_staged_file_scans_only_staged_blob() {
    let repo = TempRepo::new("h_partial");
    let file_path = repo.dir.join("partial.txt");

    // Stage secret in index, then overwrite working tree with clean content
    fs::write(&file_path, format!("SECRET={}\n", synthetic_key())).unwrap();
    repo.git_ok(&["add", "partial.txt"]);
    fs::write(&file_path, "MODE=clean_working_tree\n").unwrap();

    let out = repo.git_with_path(&["commit", "-m", "staged secret"], &path_with_test_binary());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("[SecretGuard] Git commit blocked"),
        "partially staged file with secret in index must be blocked, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_i_added_line_beginning_with_plus_plus_space_scanned() {
    let repo = TempRepo::new("i_plus_plus_space");
    fs::write(
        repo.dir.join("cpp_like.txt"),
        format!("++ {}\n", synthetic_key()),
    )
    .unwrap();
    repo.git_ok(&["add", "cpp_like.txt"]);

    let out = repo.git_with_path(
        &["commit", "-m", "plus plus space"],
        &path_with_test_binary(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("[SecretGuard] Git commit blocked"),
        "added line beginning with '++ ' containing a secret must be scanned and blocked, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_j_scanner_error_blocked() {
    let repo = TempRepo::new("j_scanner_error");
    fs::write(repo.dir.join("clean.txt"), "hello\n").unwrap();
    repo.git_ok(&["add", "clean.txt"]);

    let stub_dir = repo.dir.join("stub_bin");
    fs::create_dir_all(&stub_dir).unwrap();
    #[cfg(windows)]
    {
        fs::write(
            stub_dir.join("secretguard.cmd"),
            "@echo scanner error 1>&2\r\n@exit /b 2\r\n",
        )
        .unwrap();
        // Also provide a POSIX sh stub named secretguard for Git Bash sh.exe
        fs::write(
            stub_dir.join("secretguard"),
            "#!/bin/sh\necho 'scanner error' >&2\nexit 2\n",
        )
        .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let stub = stub_dir.join("secretguard");
        fs::write(&stub, "#!/bin/sh\necho 'scanner error' >&2\nexit 2\n").unwrap();
        let mut perms = fs::metadata(&stub).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&stub, perms).unwrap();
    }

    let out = repo.git_with_path(
        &["commit", "-m", "stub error"],
        &path_without_secretguard(Some(&stub_dir)),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("[SecretGuard] Git commit blocked"),
        "scanner non-zero error exit must block commit fail-closed, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_binary_and_raw_parser_edge_cases() {
    let repo = TempRepo::new("binary_and_parser");
    // Binary file with NUL bytes must be skipped cleanly
    fs::write(repo.dir.join("image.bin"), b"\x00\x01\x02PNG\x00\xff").unwrap();
    repo.git_ok(&["add", "image.bin"]);
    let engine = SecretGuardEngine::new();
    let findings = scan_staged_blobs_in_dir(&engine, Some(&repo.dir)).expect("scan binary");
    assert!(findings.is_empty());

    // Malformed raw -z output must fail closed
    assert!(parse_git_diff_raw_z(b"bad_header\0path\0").is_err());
    assert!(parse_git_diff_raw_z(b":100644 100644 0000 1234 A\0path\0").is_err());
}

#[test]
fn test_precommit_typechange_symlink_to_regular_file_with_secret_blocked() {
    let repo = TempRepo::new("typechange_symlink_to_file");

    // Stage a symlink (mode 120000) in Git's index without needing OS symlink privileges
    let hash_out = Command::new("git")
        .current_dir(&repo.dir)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"target.txt")
                .unwrap();
            child.wait_with_output()
        })
        .expect("git hash-object");
    assert!(hash_out.status.success());
    let oid = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();

    repo.git_ok(&[
        "update-index",
        "--add",
        "--cacheinfo",
        "120000",
        &oid,
        "entry.txt",
    ]);
    repo.git_ok(&["commit", "--no-verify", "-m", "baseline symlink"]);

    // Replace symlink with a regular file (100644) containing a synthetic secret -> typechange 'T'
    fs::write(
        repo.dir.join("entry.txt"),
        format!("API_KEY={}\n", synthetic_key()),
    )
    .unwrap();
    let new_hash = repo.git_ok(&["hash-object", "-w", "entry.txt"]);
    let new_oid = String::from_utf8_lossy(&new_hash.stdout).trim().to_string();
    repo.git_ok(&[
        "update-index",
        "--cacheinfo",
        "100644",
        &new_oid,
        "entry.txt",
    ]);

    let raw_status = repo.git_ok(&["diff", "--cached", "--name-status"]);
    assert!(
        String::from_utf8_lossy(&raw_status.stdout).contains("T\tentry.txt"),
        "expected typechange T status, got: {}",
        String::from_utf8_lossy(&raw_status.stdout)
    );

    let out = repo.git_with_path(
        &["commit", "-m", "replace symlink"],
        &path_with_test_binary(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("[SecretGuard] Git commit blocked"),
        "typechange from symlink to regular file with secret must be blocked, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_safe_hook_install_upgrade_and_custom_preservation() {
    let repo = TempRepo::new("hook_upgrade");
    let hook_path = repo.dir.join(".git").join("hooks").join("pre-commit");
    fs::remove_file(&hook_path).unwrap();

    // 1. Fresh installation
    assert_eq!(
        install_or_upgrade_pre_commit_hook(&hook_path, false).unwrap(),
        HookInstallOutcome::Installed
    );
    assert_eq!(
        fs::read_to_string(&hook_path).unwrap(),
        PRE_COMMIT_HOOK_SCRIPT
    );

    // 2. Repeat installation (idempotent)
    assert_eq!(
        install_or_upgrade_pre_commit_hook(&hook_path, false).unwrap(),
        HookInstallOutcome::AlreadyCurrent
    );

    // 3a. Upgrade from legacy install-pre-commit SecretGuard hook
    let old_main_hook = "#!/bin/sh\n# SecretGuard Git Pre-Commit Hook (Sub-millisecond Secret Interceptor)\n# https://github.com/hemanathk636/secretguard\nSTAGED_DIFF=$(git diff --cached --unified=0 2>/dev/null)\necho \"$STAGED_DIFF\" | secretguard check\n";
    fs::write(&hook_path, old_main_hook).unwrap();
    assert_eq!(
        install_or_upgrade_pre_commit_hook(&hook_path, false).unwrap(),
        HookInstallOutcome::Upgraded
    );
    assert_eq!(
        fs::read_to_string(&hook_path).unwrap(),
        PRE_COMMIT_HOOK_SCRIPT
    );

    // 3b. Upgrade from legacy SetupWizard SecretGuard hook
    let old_init_hook = "#!/bin/sh\nif command -v secretguard >/dev/null 2>&1; then\n    DIFF=$(git diff --cached --unified=0 2>/dev/null)\n    if [ -n \"$DIFF\" ]; then\n        if ! echo \"$DIFF\" | secretguard check >/dev/null 2>&1; then\n            echo \"Blocked commit: Leaked API key or secret in staged diff!\"\n            exit 1\n        fi\n    fi\nfi\nexit 0\n";
    fs::write(&hook_path, old_init_hook).unwrap();
    assert_eq!(
        install_or_upgrade_pre_commit_hook(&hook_path, false).unwrap(),
        HookInstallOutcome::Upgraded
    );
    assert_eq!(
        fs::read_to_string(&hook_path).unwrap(),
        PRE_COMMIT_HOOK_SCRIPT
    );

    // 4a. Preservation of custom hook that mentions/invokes secretguard alongside other checks
    let custom_sg_hook = "#!/bin/sh\n# Custom team hook invoking secretguard and eslint\nsecretguard check-staged || exit 1\nnpm run lint\n";
    fs::write(&hook_path, custom_sg_hook).unwrap();
    let preserve_sg_res = install_or_upgrade_pre_commit_hook(&hook_path, false);
    assert!(
        preserve_sg_res.is_err(),
        "custom hook mentioning secretguard must not be overwritten without --force"
    );
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), custom_sg_hook);

    // 4b. Preservation of unrelated/custom hook without --force
    let custom_hook = "#!/bin/sh\necho 'custom linter'\nexit 0\n";
    fs::write(&hook_path, custom_hook).unwrap();
    let preserve_res = install_or_upgrade_pre_commit_hook(&hook_path, false);
    assert!(
        preserve_res.is_err(),
        "custom hook must not be overwritten without --force"
    );
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), custom_hook);

    // Also verify CLI `install-pre-commit` without --force fails and preserves custom hook
    let cli_preserve = Command::new(env!("CARGO_BIN_EXE_secretguard"))
        .args(["install-pre-commit", repo.dir.to_str().unwrap()])
        .output()
        .expect("run install-pre-commit");
    assert!(!cli_preserve.status.success());
    assert_eq!(fs::read_to_string(&hook_path).unwrap(), custom_hook);

    // 5. Explicit --force replaces custom hook
    let cli_force = Command::new(env!("CARGO_BIN_EXE_secretguard"))
        .args(["install-pre-commit", "--force", repo.dir.to_str().unwrap()])
        .output()
        .expect("run install-pre-commit --force");
    assert!(
        cli_force.status.success(),
        "install-pre-commit --force failed: {}",
        String::from_utf8_lossy(&cli_force.stderr)
    );
    assert_eq!(
        fs::read_to_string(&hook_path).unwrap(),
        PRE_COMMIT_HOOK_SCRIPT
    );
}

#[test]
fn test_precommit_staged_blob_size_boundary_and_oversized_fail_closed() {
    let repo = TempRepo::new("blob_size_limit");
    let engine = SecretGuardEngine::new();

    // Exact boundary (1024 bytes): clean blob allowed
    let boundary_limit = 1024usize;
    let clean_exact = vec![b'a'; boundary_limit];
    fs::write(repo.dir.join("exact.txt"), &clean_exact).unwrap();
    repo.git_ok(&["add", "exact.txt"]);
    let exact_res = scan_staged_blobs_in_dir_with_limit(&engine, Some(&repo.dir), boundary_limit)
        .expect("exact boundary blob must be scanned cleanly");
    assert!(exact_res.is_empty());

    // Oversized by 1 byte (1025 bytes): must fail closed
    let mut oversized = vec![b'a'; boundary_limit + 1];
    oversized[boundary_limit] = b'\n';
    fs::write(repo.dir.join("exact.txt"), &oversized).unwrap();
    repo.git_ok(&["add", "exact.txt"]);
    let err = scan_staged_blobs_in_dir_with_limit(&engine, Some(&repo.dir), boundary_limit)
        .expect_err("oversized blob must fail closed");
    assert!(
        err.contains("exceeds maximum allowed limit"),
        "unexpected error message: {}",
        err
    );

    // Also verify default 2 MiB + 1 byte limit via CLI `check-staged`
    let over_default = vec![b'b'; DEFAULT_MAX_STAGED_BLOB_SIZE + 1];
    fs::write(repo.dir.join("exact.txt"), &over_default).unwrap();
    repo.git_ok(&["add", "exact.txt"]);
    let cli_out = Command::new(env!("CARGO_BIN_EXE_secretguard"))
        .current_dir(&repo.dir)
        .arg("check-staged")
        .output()
        .expect("run check-staged");
    assert!(
        !cli_out.status.success(),
        "oversized blob must block via CLI"
    );
    let stderr = String::from_utf8_lossy(&cli_out.stderr);
    assert!(
        stderr.contains("exceeds maximum allowed limit"),
        "expected size-limit diagnostic, got: {}",
        stderr
    );
}

#[test]
fn test_precommit_rejects_non_regular_and_symlink_hook_destinations() {
    let repo = TempRepo::new("hook_symlink_reject");
    let hook_path = repo.dir.join(".git").join("hooks").join("pre-commit");
    fs::remove_file(&hook_path).unwrap();

    // Directory at pre-commit path must be rejected (even with --force)
    fs::create_dir(&hook_path).unwrap();
    let dir_err = install_or_upgrade_pre_commit_hook(&hook_path, true)
        .expect_err("directory destination must be rejected");
    assert!(
        dir_err.contains("non-regular"),
        "unexpected error: {}",
        dir_err
    );
    assert!(hook_path.is_dir());
    fs::remove_dir(&hook_path).unwrap();

    // Missing parent directory must fail cleanly without panicking
    let missing_parent = repo
        .dir
        .join(".git")
        .join("no_such_hooks")
        .join("pre-commit");
    assert!(install_or_upgrade_pre_commit_hook(&missing_parent, true).is_err());

    // Symlink at pre-commit path must be rejected without modifying the symlink target
    let target = repo.dir.join("outside_target.sh");
    fs::write(&target, "#!/bin/sh\necho 'protected target'\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &hook_path).unwrap();
        let sym_err = install_or_upgrade_pre_commit_hook(&hook_path, true)
            .expect_err("symlink destination must be rejected even with --force");
        assert!(sym_err.contains("symlink"), "unexpected error: {}", sym_err);
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "#!/bin/sh\necho 'protected target'\n"
        );
    }
    #[cfg(windows)]
    {
        // Attempt symlink creation on Windows; if Developer Mode/SeCreateSymbolicLinkPrivilege is enabled, verify rejection
        if std::os::windows::fs::symlink_file(&target, &hook_path).is_ok() {
            let sym_err = install_or_upgrade_pre_commit_hook(&hook_path, true)
                .expect_err("symlink destination must be rejected even with --force");
            assert!(sym_err.contains("symlink"), "unexpected error: {}", sym_err);
            assert_eq!(
                fs::read_to_string(&target).unwrap(),
                "#!/bin/sh\necho 'protected target'\n"
            );
        }
    }
}

#[test]
fn test_precommit_nul_byte_and_bomless_utf16_bypass_blocked() {
    let key = synthetic_key();

    // 1. Staged file with leading NUL byte before synthetic secret -> BLOCKED
    let repo_nul = TempRepo::new("nul_prefix_staged");
    let mut nul_payload = vec![0x00u8];
    nul_payload.extend_from_slice(format!("OPENAI_API_KEY={}\n", key).as_bytes());
    fs::write(repo_nul.dir.join("nul_secret.env"), &nul_payload).unwrap();
    repo_nul.git_ok(&["add", "nul_secret.env"]);
    let out_nul = repo_nul.git_with_path(&["commit", "-m", "nul bypass"], &path_with_test_binary());
    assert!(
        !out_nul.status.success()
            && String::from_utf8_lossy(&out_nul.stderr)
                .contains("[SecretGuard] Git commit blocked"),
        "NUL byte before secret must not bypass staged commit hook"
    );

    // 2. Staged file with >4096 NUL bytes before synthetic secret -> BLOCKED
    let repo_pad = TempRepo::new("nul_pad_staged");
    let mut padded_payload = vec![0x00u8; 5000];
    padded_payload.extend_from_slice(format!("\nOPENAI_API_KEY={}\n", key).as_bytes());
    fs::write(repo_pad.dir.join("padded_secret.env"), &padded_payload).unwrap();
    repo_pad.git_ok(&["add", "padded_secret.env"]);
    let out_pad = repo_pad.git_with_path(
        &["commit", "-m", "nul pad bypass"],
        &path_with_test_binary(),
    );
    assert!(
        !out_pad.status.success()
            && String::from_utf8_lossy(&out_pad.stderr)
                .contains("[SecretGuard] Git commit blocked"),
        "5000 prepended NUL bytes must not bypass staged commit hook"
    );

    // 2b. Staged file with NUL bytes embedded inside the secret token -> BLOCKED
    let repo_inside = TempRepo::new("nul_inside_staged");
    let mut inside_payload = Vec::new();
    inside_payload.extend_from_slice(b"OPENAI_API_KEY=");
    inside_payload.extend_from_slice(&key.as_bytes()[..7]);
    inside_payload.push(0x00);
    inside_payload.extend_from_slice(&key.as_bytes()[7..13]);
    inside_payload.push(0x00);
    inside_payload.extend_from_slice(&key.as_bytes()[13..]);
    inside_payload.push(b'\n');
    fs::write(
        repo_inside.dir.join("nul_inside_secret.env"),
        &inside_payload,
    )
    .unwrap();
    repo_inside.git_ok(&["add", "nul_inside_secret.env"]);
    let out_inside = repo_inside.git_with_path(
        &["commit", "-m", "nul inside bypass"],
        &path_with_test_binary(),
    );
    assert!(
        !out_inside.status.success()
            && String::from_utf8_lossy(&out_inside.stderr)
                .contains("[SecretGuard] Git commit blocked"),
        "NUL bytes inside secret token must not bypass staged commit hook"
    );

    // 3. Staged BOM-less UTF-16LE and UTF-16BE files -> BLOCKED
    for (name, is_le) in [("bomless_le.env", true), ("bomless_be.env", false)] {
        let repo_u16 = TempRepo::new(name);
        let content = format!("OPENAI_API_KEY={}\n", key);
        let mut bytes = Vec::new();
        for u in content.encode_utf16() {
            if is_le {
                bytes.extend_from_slice(&u.to_le_bytes());
            } else {
                bytes.extend_from_slice(&u.to_be_bytes());
            }
        }
        fs::write(repo_u16.dir.join(name), &bytes).unwrap();
        repo_u16.git_ok(&["add", name]);
        let out_u16 = repo_u16.git_with_path(&["commit", "-m", name], &path_with_test_binary());
        assert!(
            !out_u16.status.success()
                && String::from_utf8_lossy(&out_u16.stderr)
                    .contains("[SecretGuard] Git commit blocked"),
            "BOM-less UTF-16 ({}) with secret must be blocked",
            name
        );
    }
}
