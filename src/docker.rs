use crate::SecretGuardEngine;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerLayerLeak {
    pub line_number: usize,
    pub instruction: String,
    pub raw_line: String,
    pub detected_secrets: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerScanReport {
    pub dockerfile_path: String,
    pub leaks: Vec<DockerLayerLeak>,
    pub clean: bool,
}

pub struct DockerScanner;

impl DockerScanner {
    /// Scans a Dockerfile for baked-in environment variables, build arguments, or hardcoded secrets
    pub fn scan_dockerfile(
        path: &Path,
        engine: &SecretGuardEngine,
    ) -> Result<DockerScanReport, String> {
        if !path.exists() {
            return Err(format!("Dockerfile not found at: {}", path.display()));
        }

        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read Dockerfile: {}", e))?;

        let mut leaks = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let upper = trimmed.to_uppercase();
            let is_copy_dot = upper.starts_with("COPY . .") || upper.starts_with("ADD . .");

            // 1. Scan for actual secret patterns in the line
            let res = engine.scan_and_sanitize(trimmed);
            if res.has_secret {
                leaks.push(DockerLayerLeak {
                    line_number: idx + 1,
                    instruction: trimmed.split_whitespace().next().unwrap_or("").to_string(),
                    raw_line: res.sanitized_text,
                    detected_secrets: res.matched_rules,
                    recommendation: "Never bake secrets into ENV or ARG directives. Use Docker BuildKit secrets: `RUN --mount=type=secret...`".to_string(),
                });
            } else if is_copy_dot {
                // Warning on unrestricted COPY . . without verified .dockerignore
                leaks.push(DockerLayerLeak {
                    line_number: idx + 1,
                    instruction: "COPY".to_string(),
                    raw_line: trimmed.to_string(),
                    detected_secrets: vec!["Dangerous Unrestricted Directory Copy".to_string()],
                    recommendation: "Ensure .env and credentials are listed in .dockerignore so they are not baked into public image layers.".to_string(),
                });
            }
        }

        let clean = leaks.is_empty();
        Ok(DockerScanReport {
            dockerfile_path: path.display().to_string(),
            leaks,
            clean,
        })
    }

    /// CLI Handler for `secretguard docker`
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        let dockerfile_path = if !args.is_empty() && !args[0].starts_with('-') {
            Path::new(&args[0])
        } else {
            Path::new("Dockerfile")
        };

        println!(
            "🐳 Running Docker Layer & Build Argument X-Ray on \x1b[36m{}\x1b[0m...\n",
            dockerfile_path.display()
        );

        match Self::scan_dockerfile(dockerfile_path, engine) {
            Ok(report) => {
                if report.clean {
                    println!("✅ 100% Clean! Zero hardcoded credentials or risky build layer copies found in Dockerfile.");
                } else {
                    println!(
                        "🚨 Detected {} Docker image security vulnerabilities:\n",
                        report.leaks.len()
                    );
                    for leak in &report.leaks {
                        println!(
                            "  • \x1b[31mLine {}\x1b[0m [{}]: \x1b[33m{}\x1b[0m",
                            leak.line_number, leak.instruction, leak.raw_line
                        );
                        println!(
                            "    ├── Detected: \x1b[36m{}\x1b[0m",
                            leak.detected_secrets.join(", ")
                        );
                        println!("    └── Fix:      {}", leak.recommendation);
                        println!();
                    }
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("❌ Docker scan error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
