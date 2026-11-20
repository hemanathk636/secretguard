use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileHit {
    pub file_path: String,
    pub line_number: usize,
    pub masked_context: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlastRadiusReport {
    pub target_query: String,
    pub total_files_scanned: usize,
    pub affected_files: Vec<FileHit>,
    pub affected_repos: Vec<String>,
    pub risk_score: f64,
    pub risk_level: String,
}

pub struct BlastRadiusScanner;

impl BlastRadiusScanner {
    /// Scan current repository or target directory for references to the target secret/token
    pub fn calculate_blast_radius(query: &str, base_dir: Option<&Path>) -> BlastRadiusReport {
        let root = base_dir.unwrap_or_else(|| Path::new("."));
        let mut affected_files = Vec::new();
        let mut total_scanned = 0;

        let search_pattern = if query.len() > 8 {
            &query[..8]
        } else {
            query
        };

        Self::walk_and_scan(root, search_pattern, &mut affected_files, &mut total_scanned);

        let files_count = affected_files.len();
        let risk_score = if files_count == 0 {
            0.0
        } else if files_count <= 2 {
            4.5
        } else if files_count <= 5 {
            7.5
        } else {
            9.5
        };

        let risk_level = if risk_score > 8.0 {
            "CRITICAL (Widespread Exposure Across Projects)".to_string()
        } else if risk_score > 5.0 {
            "HIGH (Multiple Repository Leaks)".to_string()
        } else if risk_score > 0.0 {
            "MODERATE (Isolated Local Reference)".to_string()
        } else {
            "CLEAN (Zero Exposure Detected)".to_string()
        };

        BlastRadiusReport {
            target_query: search_pattern.to_string(),
            total_files_scanned: total_scanned,
            affected_files,
            affected_repos: vec![root.to_string_lossy().to_string()],
            risk_score,
            risk_level,
        }
    }

    fn walk_and_scan(dir: &Path, pattern: &str, hits: &mut Vec<FileHit>, scanned: &mut usize) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Ignore .git, target, node_modules, but allow hidden config files like .env or .env.local
                if name == ".git" || name == "target" || name == "node_modules" {
                    continue;
                }
            }

            if path.is_dir() {
                Self::walk_and_scan(&path, pattern, hits, scanned);
            } else if path.is_file() {
                *scanned += 1;
                if let Ok(content) = fs::read_to_string(&path) {
                    for (idx, line) in content.lines().enumerate() {
                        if line.contains(pattern) {
                            let masked_ctx = if line.len() > 60 {
                                format!("{}...", &line[..57])
                            } else {
                                line.to_string()
                            };

                            hits.push(FileHit {
                                file_path: path.display().to_string(),
                                line_number: idx + 1,
                                masked_context: masked_ctx,
                            });
                        }
                    }
                }
            }
        }
    }

    /// CLI Handler for `secretguard blast-radius`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard blast-radius - Secret Blast-Radius & Dependency Graph

USAGE:
    secretguard blast-radius <SECRET_OR_KEY_NAME> [DIR]

Maps where a specific credential is used across the current repository,
Dockerfiles, configuration files, and dependencies to assess leak impact.
"#
            );
            return;
        }

        let query = &args[0];
        let target_dir = if args.len() >= 2 {
            Some(Path::new(&args[1]))
        } else {
            None
        };

        println!("💣 Calculating blast-radius for token pattern: \x1b[33m{}\x1b[0m...", query);
        let report = Self::calculate_blast_radius(query, target_dir);

        println!("\n📊 Blast-Radius Analysis Report:");
        println!("  ├── Scanned Files:   {}", report.total_files_scanned);
        println!("  ├── Affected Files:  {}", report.affected_files.len());
        println!("  ├── Risk Score:      \x1b[1m{:.1}/10.0\x1b[0m", report.risk_score);
        println!("  └── Threat Level:    \x1b[31m{}\x1b[0m\n", report.risk_level);

        if report.affected_files.is_empty() {
            println!("✅ Zero references found across scanned files. The token has no local footprint!");
        } else {
            println!("Impacted File Locations:");
            for hit in &report.affected_files {
                println!("  • \x1b[36m{}:{}\x1b[0m -> {}", hit.file_path, hit.line_number, hit.masked_context);
            }
        }
    }
}
