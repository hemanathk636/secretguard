use std::process::Command;

#[test]
fn test_pillar_help_screens() {
    let cargo_bin = env!("CARGO_BIN_EXE_secretguard");

    // 1. Master help
    let output = Command::new(cargo_bin)
        .arg("--help")
        .output()
        .expect("Failed to run binary");
    let err_str = String::from_utf8_lossy(&output.stderr);
    let out_str = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", out_str, err_str);
    assert!(combined.contains("THE 3 SECURITY PILLARS"));
    assert!(combined.contains("shield"));
    assert!(combined.contains("vault"));
    assert!(combined.contains("audit"));

    // 2. Pillar 1: Shield help
    let output = Command::new(cargo_bin)
        .args(["shield", "--help"])
        .output()
        .expect("Failed to run shield help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("SecretGuard Shield — Pillar 1: Ambient Shield & Runtime Defense"));
    assert!(combined.contains("hook"));
    assert!(combined.contains("tun"));
    assert!(combined.contains("wrap"));
    assert!(combined.contains("screen"));

    // 3. Pillar 2: Vault help
    let output = Command::new(cargo_bin)
        .args(["vault", "--help"])
        .output()
        .expect("Failed to run vault help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("SecretGuard Vault — Pillar 2: Zero-Knowledge Keystore & Team Mesh"));
    assert!(combined.contains("init"));
    assert!(combined.contains("mesh"));
    assert!(combined.contains("canary"));

    // 4. Pillar 3: Audit help
    let output = Command::new(cargo_bin)
        .args(["audit", "--help"])
        .output()
        .expect("Failed to run audit help");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("SecretGuard Audit — Pillar 3: Repository Auditing & Remediation"));
    assert!(combined.contains("scan"));
    assert!(combined.contains("git"));
    assert!(combined.contains("docker"));
    assert!(combined.contains("report"));
}

#[test]
fn test_pillar_execution_and_aliases() {
    let cargo_bin = env!("CARGO_BIN_EXE_secretguard");

    // 1. Pillar 1 execution: secretguard shield hook zsh
    let output = Command::new(cargo_bin)
        .args(["shield", "hook", "zsh"])
        .output()
        .expect("Failed to run shield hook");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("zshaddhistory()"));

    // Shortcut alias: secretguard hook zsh
    let output_alias = Command::new(cargo_bin)
        .args(["hook", "zsh"])
        .output()
        .expect("Failed to run shortcut hook");
    assert_eq!(stdout, String::from_utf8_lossy(&output_alias.stdout));

    // 2. Pillar 3 execution: secretguard audit scan --json
    let output = Command::new(cargo_bin)
        .args(["audit", "scan", "Cargo.toml", "--json"])
        .output()
        .expect("Failed to run audit scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"target\": \"Cargo.toml\""));
    assert!(stdout.contains("\"files_scanned\": 1"));
    assert!(stdout.contains("\"clean\": true"));
}
