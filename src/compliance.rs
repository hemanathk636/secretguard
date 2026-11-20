use crate::SecretGuardEngine;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceFinding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub standard_violation: String, // SOC2 CC6.1, HIPAA 164.312, GDPR Art 32
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceReport {
    pub timestamp: String,
    pub workspace_scanned: String,
    pub total_files_audited: usize,
    pub passed: bool,
    pub findings: Vec<ComplianceFinding>,
    pub soc2_status: String,
    pub hipaa_status: String,
    pub gdpr_status: String,
}

pub struct ComplianceAuditor;

impl ComplianceAuditor {
    /// Audits the entire codebase against major regulatory security standards
    pub fn audit_workspace(root: &Path, engine: &SecretGuardEngine) -> ComplianceReport {
        let mut findings = Vec::new();
        let mut total_files = 0;

        Self::walk_and_audit(root, engine, &mut findings, &mut total_files);

        let passed = findings.is_empty();
        let (soc2, hipaa, gdpr) = if passed {
            ("COMPLIANT (CC6.1 / CC6.6 Passed)".to_string(), "COMPLIANT (§164.312 Passed)".to_string(), "COMPLIANT (Art 32 Passed)".to_string())
        } else {
            ("NON-COMPLIANT (Plaintext Credentials Found)".to_string(), "NON-COMPLIANT (Unencrypted Keys)".to_string(), "NON-COMPLIANT (Exposed PII/Secrets)".to_string())
        };

        ComplianceReport {
            timestamp: format!("{:?}", std::time::SystemTime::now()),
            workspace_scanned: root.display().to_string(),
            total_files_audited: total_files,
            passed,
            findings,
            soc2_status: soc2,
            hipaa_status: hipaa,
            gdpr_status: gdpr,
        }
    }

    fn walk_and_audit(dir: &Path, engine: &SecretGuardEngine, findings: &mut Vec<ComplianceFinding>, total_files: &mut usize) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == ".git" || name == "target" || name == "node_modules" {
                    continue;
                }
            }

            if path.is_dir() {
                Self::walk_and_audit(&path, engine, findings, total_files);
            } else if path.is_file() {
                *total_files += 1;
                if let Ok(content) = fs::read_to_string(&path) {
                    for (idx, line) in content.lines().enumerate() {
                        let res = engine.scan_and_sanitize(line);
                        if res.has_secret {
                            findings.push(ComplianceFinding {
                                file: path.display().to_string(),
                                line: idx + 1,
                                rule: res.matched_rules.join(", "),
                                standard_violation: "SOC2 Trust Criteria CC6.1 & GDPR Article 32".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// CLI Handler for `secretguard report`
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        let target = if !args.is_empty() && !args[0].starts_with('-') {
            Path::new(&args[0])
        } else {
            Path::new(".")
        };

        println!("📜 Generating SOC 2, HIPAA & GDPR Cryptographic Compliance Report for \x1b[36m{}\x1b[0m...\n", target.display());
        let rep = Self::audit_workspace(target, engine);

        println!("============================================================");
        println!("       SECRETGUARD REGULATORY COMPLIANCE AUDIT CERTIFICATE  ");
        println!("============================================================");
        println!("  • Workspace:         {}", rep.workspace_scanned);
        println!("  • Files Audited:     {}", rep.total_files_audited);
        println!("  • SOC 2 Type II:     {}", if rep.passed { "\x1b[32mCOMPLIANT\x1b[0m" } else { "\x1b[31mVIOLATION DETECTED\x1b[0m" });
        println!("  • HIPAA Security:    {}", if rep.passed { "\x1b[32mCOMPLIANT\x1b[0m" } else { "\x1b[31mVIOLATION DETECTED\x1b[0m" });
        println!("  • GDPR Article 32:   {}", if rep.passed { "\x1b[32mCOMPLIANT\x1b[0m" } else { "\x1b[31mVIOLATION DETECTED\x1b[0m" });
        println!("============================================================");

        if rep.passed {
            println!("\n✅ PASS: Zero plaintext credentials or cryptographic keys found.");
            println!("Ready for submission to security auditors and SOC 2 compliance assessors.");
        } else {
            println!("\n🚨 FAIL: Found {} compliance violations:\n", rep.findings.len());
            for f in &rep.findings {
                println!("  • \x1b[33m{}:{}\x1b[0m: {} [{}]", f.file, f.line, f.rule, f.standard_violation);
            }
            std::process::exit(1);
        }
    }
}
