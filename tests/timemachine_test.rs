use secretguard::timemachine::TimeMachine;
use secretguard::SecretGuardEngine;
use std::fs;
use std::process::Command;

#[test]
fn test_timemachine_git_detection() {
    let _engine = SecretGuardEngine::new();

    // Create a self-contained temp directory to test both non-git and git scenarios
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_tm_detect_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    // Verify non-git directory returns false
    assert!(
        !TimeMachine::is_git_repo(Some(&temp_dir)),
        "Fresh directory without .git must not be identified as a git repo"
    );

    // Initialize git repository
    let run = |args: &[&str]| {
        Command::new("git")
            .current_dir(&temp_dir)
            .args(args)
            .output()
            .expect("git command failed")
    };

    run(&["init"]);
    run(&["config", "user.email", "test@secretguard.dev"]);
    run(&["config", "user.name", "SecretGuard Test"]);

    // Verify it is now recognized as a git repository
    assert!(
        TimeMachine::is_git_repo(Some(&temp_dir)),
        "Initialized repository must be recognized"
    );

    // Make an initial commit
    let test_file = temp_dir.join("init.txt");
    fs::write(&test_file, "initial commit content\n").unwrap();
    run(&["add", "init.txt"]);
    run(&["commit", "-m", "Initial commit"]);

    let commits = TimeMachine::get_commit_hashes(Some(&temp_dir), Some(5)).unwrap();
    assert_eq!(
        commits.len(),
        1,
        "Must find exactly 1 commit in self-contained repo"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_timemachine_scan_temp_repo() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_tm_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    fs::write(
        &secret_file,
        "API_KEY=sk-test0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    run(&["add", "config.env"]);
    run(&["commit", "-m", "Accidental secret leak"]);

    let report_tainted = TimeMachine::scan_history(&engine, Some(&temp_dir), None).unwrap();
    assert_eq!(report_tainted.total_commits_scanned, 2);
    assert!(!report_tainted.clean);
    assert_eq!(report_tainted.tainted_commits.len(), 1);
    assert_eq!(
        report_tainted.tainted_commits[0].summary,
        "Accidental secret leak"
    );

    // Test Dry Run Scrub
    let dry_run_res = TimeMachine::scrub_history(&engine, Some(&temp_dir), true).unwrap();
    assert!(dry_run_res.success);
    assert_eq!(dry_run_res.commits_scrubbed, 1);

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
