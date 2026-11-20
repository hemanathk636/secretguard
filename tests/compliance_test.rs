use secretguard::compliance::ComplianceAuditor;
use secretguard::SecretGuardEngine;
use std::fs;

#[test]
fn test_compliance_report_generator() {
    let engine = SecretGuardEngine::new();
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_audit_test_{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Clean workspace passes
    let clean_file = temp_dir.join("index.js");
    fs::write(&clean_file, "console.log('clean codebase');\n").unwrap();

    let clean_rep = ComplianceAuditor::audit_workspace(&temp_dir, &engine);
    assert!(clean_rep.passed);
    assert!(clean_rep.soc2_status.contains("COMPLIANT"));
    assert_eq!(clean_rep.findings.len(), 0);

    // 2. Tainted workspace fails with specific violations
    let tainted_file = temp_dir.join("leaked.env");
    fs::write(&tainted_file, "SECRET_TOKEN=sk-proj-1234567890abcdef1234567890abcdef1234567890\n").unwrap();

    let tainted_rep = ComplianceAuditor::audit_workspace(&temp_dir, &engine);
    assert!(!tainted_rep.passed);
    assert!(tainted_rep.soc2_status.contains("NON-COMPLIANT"));
    assert_eq!(tainted_rep.findings.len(), 1);
    assert!(tainted_rep.findings[0].standard_violation.contains("SOC2"));

    let _ = fs::remove_dir_all(&temp_dir);
}
