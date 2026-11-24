use secretguard::completions::CompletionsGenerator;
use secretguard::ghost::GhostVirtualizer;
use secretguard::immune::ImmuneEngine;
use secretguard::SecretGuardEngine;
use std::process::Command;

#[test]
fn test_ghost_tokens_generation() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_futuristic_ghost_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    std::env::set_var("SECRETGUARD_DIR", &temp_dir);

    let engine = SecretGuardEngine::new();

    // 1. OpenAI Key
    let real_openai = "sk-proj-abc1234567890123456789012345678901234567890";
    let ghost_openai = GhostVirtualizer::create_ghost_token(real_openai);
    assert!(ghost_openai.starts_with("sk-ghost-"));
    assert_ne!(ghost_openai, real_openai);

    // 2. AWS Key
    let real_aws = "AKIAIOSFODNN7EXAMPLE";
    let ghost_aws = GhostVirtualizer::create_ghost_token(real_aws);
    assert!(ghost_aws.starts_with("AKIA_GHOST_"));
    assert_ne!(ghost_aws, real_aws);

    // 3. Virtualize text
    let prompt_text = format!("Testing OpenAI {} with AWS {}", real_openai, real_aws);
    let (virtualized, count) = GhostVirtualizer::virtualize_text(&prompt_text, &engine);

    assert!(!virtualized.contains(real_openai));
    assert!(!virtualized.contains(real_aws));
    assert!(virtualized.contains("sk-ghost-"));
    assert!(virtualized.contains("AKIA_GHOST_"));
    assert_eq!(count, 2);

    std::env::remove_var("SECRETGUARD_DIR");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_immune_engine_containment() {
    let engine = SecretGuardEngine::new();

    // Test simulated containment on exposed OpenAI key
    let exposed_token = "sk-proj-leakedTokenEmergencyTest1234567890";
    let report = ImmuneEngine::trigger_containment(exposed_token, &engine)
        .expect("Containment should succeed");

    assert_eq!(report.provider, "OpenAI API");
    assert!(
        report.revocation_status.contains("OpenAI")
            || report.revocation_status.contains("CIRCUIT-BREAKER")
    );
    assert!(report.quarantine_id.starts_with("quarantine_openai_api_"));
    assert!(!report.lifecycle_state.is_empty());
    assert!(report.containment_latency_ms < 2000); // SLA verification
}

#[test]
fn test_shell_completions_generation() {
    let zsh = CompletionsGenerator::generate_zsh();
    assert!(zsh.contains("#compdef secretguard"));
    assert!(zsh.contains("ghost:Zero-Knowledge LLM Context Virtualization"));
    assert!(zsh.contains("immune:Autonomous self-healing"));

    let bash = CompletionsGenerator::generate_bash();
    assert!(bash.contains("_secretguard_completions()"));
    assert!(bash.contains("ghost"));
    assert!(bash.contains("immune"));

    let pwsh = CompletionsGenerator::generate_powershell();
    assert!(pwsh.contains("Register-ArgumentCompleter"));
    assert!(pwsh.contains("init"));
}

#[test]
fn test_cli_dispatch_futuristic_commands() {
    let cargo_bin = env!("CARGO_BIN_EXE_secretguard");

    // 1. completions
    let output = Command::new(cargo_bin)
        .args(["completions", "zsh"])
        .output()
        .expect("Failed to run completions");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("#compdef secretguard"));

    // 2. ghost inspect
    let output = Command::new(cargo_bin)
        .args(["ghost", "inspect"])
        .output()
        .expect("Failed to run ghost inspect");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SecretGuard Zero-Knowledge Ghost Session Table"));

    // 3. immune status
    let output = Command::new(cargo_bin)
        .args(["immune", "status"])
        .output()
        .expect("Failed to run immune status");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SecretGuard Immune System Status"));
    assert!(stdout.contains("Mean Time to Contain (MTTC)"));
}
