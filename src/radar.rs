use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnicodeThreatHit {
    pub file_path: String,
    pub line_number: usize,
    pub threat_type: String,
    pub char_hex: String,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnicodeRadarReport {
    pub total_files_scanned: usize,
    pub threats_found: Vec<UnicodeThreatHit>,
    pub clean: bool,
}

pub struct UnicodeRadar;

impl UnicodeRadar {
    /// Detects Trojan Source (CVE-2021-42574), zero-width prompt injection characters, and homoglyphs
    pub fn scan_text(text: &str, file_path: &str) -> Vec<UnicodeThreatHit> {
        let mut threats = Vec::new();

        for (line_idx, line) in text.lines().enumerate() {
            for (col_idx, c) in line.chars().enumerate() {
                let u = c as u32;

                // Ignore standard Unicode Byte Order Mark (BOM) at the start of a file
                if line_idx == 0 && col_idx == 0 && u == 0xFEFF {
                    continue;
                }

                // 1. Bidirectional Override Characters (Trojan Source - CVE-2021-42574)
                if matches!(u, 0x202A..=0x202E | 0x2066..=0x2069) {
                    threats.push(UnicodeThreatHit {
                        file_path: file_path.to_string(),
                        line_number: line_idx + 1,
                        threat_type: "Trojan Source (BiDi Override)".to_string(),
                        char_hex: format!("U+{:04X}", u),
                        description: "Invisible bidirectional control character capable of flipping visual code ordering (CVE-2021-42574)".to_string(),
                    });
                }

                // 2. Invisible Zero-Width Characters (AI Prompt Injection Vector)
                if matches!(
                    u,
                    0x200B | 0x200C | 0x200D | 0xFEFF | 0x2060 | 0x200E | 0x200F
                ) {
                    threats.push(UnicodeThreatHit {
                        file_path: file_path.to_string(),
                        line_number: line_idx + 1,
                        threat_type: "Zero-Width Prompt Injection Vector".to_string(),
                        char_hex: format!("U+{:04X}", u),
                        description: "Invisible zero-width character frequently used to hide backdoor instructions from human reviewers while triggering LLMs".to_string(),
                    });
                }
            }
        }

        threats
    }

    /// Recursively scan codebase or directory for stealth Unicode threats
    pub fn scan_path(target_path: &Path) -> Result<UnicodeRadarReport, String> {
        let mut threats = Vec::new();
        let mut total_files = 0;
        let ignores = Self::load_ignore_patterns(target_path);

        Self::walk_and_scan(target_path, &mut threats, &mut total_files, &ignores);

        let clean = threats.is_empty();
        Ok(UnicodeRadarReport {
            total_files_scanned: total_files,
            threats_found: threats,
            clean,
        })
    }

    fn load_ignore_patterns(root: &Path) -> Vec<String> {
        let mut ignores = vec![
            "target".to_string(),
            "node_modules".to_string(),
            "dist".to_string(),
            "build".to_string(),
            ".git".to_string(),
        ];
        let ignore_file = root.join(".secretguardignore");
        let content_res =
            fs::read_to_string(&ignore_file).or_else(|_| fs::read_to_string(".secretguardignore"));
        if let Ok(content) = content_res {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    ignores.push(
                        trimmed
                            .trim_end_matches('/')
                            .trim_end_matches('\\')
                            .to_string(),
                    );
                }
            }
        }
        ignores
    }

    fn is_ignored(path: &Path, name: &str, ignores: &[String]) -> bool {
        if name == ".git" {
            return true;
        }
        let p_str = path.to_string_lossy().replace('\\', "/");
        ignores.iter().any(|ig| {
            let ig_norm = ig.replace('\\', "/");
            name == *ig
                || p_str.ends_with(&ig_norm)
                || p_str.contains(&format!("/{}/", ig_norm))
                || p_str.starts_with(&format!("{}/", ig_norm))
        })
    }

    fn walk_and_scan(
        dir: &Path,
        threats: &mut Vec<UnicodeThreatHit>,
        total_files: &mut usize,
        ignores: &[String],
    ) {
        if dir.is_file() {
            *total_files += 1;
            if let Ok(content) = fs::read_to_string(dir) {
                let hits = Self::scan_text(&content, &dir.display().to_string());
                threats.extend(hits);
            }
            return;
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            if Self::is_ignored(&path, name, ignores) {
                continue;
            }

            if path.is_dir() {
                Self::walk_and_scan(&path, threats, total_files, ignores);
            } else if path.is_file() {
                *total_files += 1;
                if let Ok(content) = fs::read_to_string(&path) {
                    let hits = Self::scan_text(&content, &path.display().to_string());
                    threats.extend(hits);
                }
            }
        }
    }

    /// Surgically strip invisible characters from a string
    pub fn strip_invisible_characters(text: &str) -> String {
        text.chars()
            .filter(|&c| {
                let u = c as u32;
                !matches!(
                    u,
                    0x202A..=0x202E | 0x2066..=0x2069 | 0x200B | 0x200C | 0x200D | 0xFEFF | 0x2060 | 0x200E | 0x200F
                )
            })
            .collect()
    }

    /// CLI Handler for `secretguard radar`
    pub fn run_cli(args: &[String]) {
        let target = if !args.is_empty() && !args[0].starts_with('-') {
            Path::new(&args[0])
        } else {
            Path::new(".")
        };

        println!("🦹 Scanning for Trojan Source & Invisible Zero-Width Attack Vectors in \x1b[36m{}\x1b[0m...", target.display());

        match Self::scan_path(target) {
            Ok(report) => {
                println!("📊 Scanned {} source files.", report.total_files_scanned);
                if report.clean {
                    println!("✅ 100% Clean! Zero invisible homoglyphs, BiDi overrides, or zero-width prompt injections detected.");
                } else {
                    println!(
                        "🚨 Detected {} stealth Unicode threats:\n",
                        report.threats_found.len()
                    );
                    for t in &report.threats_found {
                        println!(
                            "  • \x1b[31m{}\x1b[0m [{}] at \x1b[33m{}:{}\x1b[0m",
                            t.threat_type, t.char_hex, t.file_path, t.line_number
                        );
                        println!("    └── {}", t.description);
                    }
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("❌ Scan failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}
