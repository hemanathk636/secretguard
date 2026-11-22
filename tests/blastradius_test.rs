use secretguard::blastradius::BlastRadiusScanner;
use std::fs;

#[test]
fn test_blast_radius_detection() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_br_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let secret_to_track = "sk-tracked-unique-testkey-123456";

    // File 1: Leaks in env
    let f1 = temp_dir.join(".env.local");
    fs::write(&f1, format!("OPENAI_KEY={}\n", secret_to_track)).unwrap();

    // File 2: Leaks in config
    let f2 = temp_dir.join("config.json");
    fs::write(&f2, format!("{{\"api_key\":\"{}\"}}\n", secret_to_track)).unwrap();

    // File 3: Clean file
    let f3 = temp_dir.join("server.js");
    fs::write(&f3, "console.log('clean server running');\n").unwrap();

    let report = BlastRadiusScanner::calculate_blast_radius(secret_to_track, Some(&temp_dir));
    assert_eq!(report.affected_files.len(), 2);
    assert!(report.risk_score > 0.0);
    assert!(report.total_files_scanned >= 3);

    // Track a secret that doesn't exist
    let report_clean =
        BlastRadiusScanner::calculate_blast_radius("nonexistent-key-999", Some(&temp_dir));
    assert_eq!(report_clean.affected_files.len(), 0);
    assert_eq!(report_clean.risk_score, 0.0);

    let _ = fs::remove_dir_all(&temp_dir);
}
