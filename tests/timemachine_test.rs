use secretguard::timemachine::TimeMachine;
use secretguard::SecretGuardEngine;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_timemachine_git_detection() {
    let _engine = SecretGuardEngine::new();
    let is_repo = TimeMachine::is_git_repo(Some(Path::new(".")));
    assert!(is_repo, "SecretGuard workspace must be a git repository");

    let commits = TimeMachine::get_commit_hashes(Some(Path::new(".")), Some(5)).unwrap();
    assert!(!commits.is_empty(), "Must find git commits");
}

#[test]
fn test_timemachine_scan_temp_repo() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!("sg_tm_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&temp_dir).unwrap();

    // Init a git repo
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .current_dir(&temp_dir)
            .args(args)
            .status()
            .expect("git failed");
        assert!(status.success());
    };

    run(&["init"]);
    run(&["config", "user.email", "test@secretguard.dev"]);
    run(&["config", "user.name", "SecretGuard Test"]);

    // Commit 1: Clean file
    let clean_file = temp_dir.join("clean.txt");
    fs::write(&clean_file, "Hello clean world\n").unwrap();
    run(&["add", "clean.txt"]);
    run(&["commit", "-m", "Initial clean commit"]);

    let report_clean = TimeMachine::scan_history(&engine, Some(&temp_dir), None).unwrap();
    assert_eq!(report_clean.total_commits_scanned, 1);
    assert!(report_clean.clean);

    // Commit 2: Leaked key (use test prefix that won't trigger push protections)
    let secret_file = temp_dir.join("config.env");
    fs::write(&secret_file, "API_KEY=sk-test0123456789abcdef0123456789abcdef\n").unwrap();
    run(&["add", "config.env"]);
    run(&["commit", "-m", "Accidental secret leak"]);

    let report_tainted = TimeMachine::scan_history(&engine, Some(&temp_dir), None).unwrap();
    assert_eq!(report_tainted.total_commits_scanned, 2);
    assert!(!report_tainted.clean);
    assert_eq!(report_tainted.tainted_commits.len(), 1);
    assert_eq!(report_tainted.tainted_commits[0].summary, "Accidental secret leak");

    // Test Dry Run Scrub
    let dry_run_res = TimeMachine::scrub_history(&engine, Some(&temp_dir), true).unwrap();
    assert!(dry_run_res.success);
    assert_eq!(dry_run_res.commits_scrubbed, 1);

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
