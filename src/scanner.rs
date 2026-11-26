use crate::{Confidence, FindingMatch, SecretGuardEngine, Severity};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB
pub const DEFAULT_MAX_FINDINGS: usize = 100;
const MINIFIED_LINE_THRESHOLD: usize = 4000;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: PathBuf,
    pub json_mode: bool,
    pub compact: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub all_files: bool,
    pub max_file_size: u64,
    pub max_findings: usize,
    pub excludes: Vec<String>,
    pub includes: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: PathBuf::from("."),
            json_mode: false,
            compact: false,
            quiet: false,
            verbose: false,
            all_files: false,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_findings: DEFAULT_MAX_FINDINGS,
            excludes: Vec::new(),
            includes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanFinding {
    pub finding_id: String,
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    pub redacted_snippet: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingGroup {
    pub group_id: String,
    pub file: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    pub occurrences: usize,
    pub lines: Vec<usize>,
    pub sample_redacted: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub leaks_found: usize,
    pub unique_groups: usize,
    pub errors_encountered: usize,
    pub symlinks_skipped: usize,
    pub files_ignored: usize,
    pub binary_files_skipped: usize,
    pub large_files_skipped: usize,
    pub vanished_files_skipped: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub status: String,
    pub clean: bool,
    pub stats: ScanStats,
    pub findings: Vec<ScanFinding>,
    pub groups: Vec<FindingGroup>,
    pub skipped_details: Vec<String>,
    pub scan_duration_ms: u128,
}

pub fn parse_size_arg(raw: &str) -> Result<u64, String> {
    let s = raw.trim().to_ascii_uppercase();
    if let Some(num) = s.strip_suffix("GB") {
        num.trim()
            .parse::<u64>()
            .map(|n| n.saturating_mul(1024 * 1024 * 1024))
            .map_err(|_| format!("Invalid size '{}'", raw))
    } else if let Some(num) = s.strip_suffix("MB") {
        num.trim()
            .parse::<u64>()
            .map(|n| n.saturating_mul(1024 * 1024))
            .map_err(|_| format!("Invalid size '{}'", raw))
    } else if let Some(num) = s.strip_suffix("KB") {
        num.trim()
            .parse::<u64>()
            .map(|n| n.saturating_mul(1024))
            .map_err(|_| format!("Invalid size '{}'", raw))
    } else if let Some(num) = s.strip_suffix('B') {
        num.trim()
            .parse::<u64>()
            .map_err(|_| format!("Invalid size '{}'", raw))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("Invalid size '{}'", raw))
    }
}

fn load_ignore_patterns(extra_excludes: &[String]) -> Vec<String> {
    let mut ignores = vec![
        "target".to_string(),
        "node_modules".to_string(),
        "vendor".to_string(),
        "dist".to_string(),
        "build".to_string(),
        ".git".to_string(),
    ];
    if let Ok(content) = std::fs::read_to_string(".secretguardignore") {
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
    for ex in extra_excludes {
        let trimmed = ex.trim();
        if !trimmed.is_empty() {
            ignores.push(
                trimmed
                    .trim_end_matches('/')
                    .trim_end_matches('\\')
                    .to_string(),
            );
        }
    }
    ignores
}

fn matches_pattern_list(path: &Path, name: &str, patterns: &[String]) -> bool {
    let p_str = path.to_string_lossy().replace('\\', "/");
    patterns.iter().any(|pat| {
        let pat_norm = pat.replace('\\', "/");
        if let Some(ext_pat) = pat_norm.strip_prefix("*.") {
            return name.ends_with(&format!(".{}", ext_pat));
        }
        name == pat_norm
            || p_str.ends_with(&pat_norm)
            || p_str.contains(&format!("/{}/", pat_norm))
            || p_str.starts_with(&format!("{}/", pat_norm))
    })
}

fn is_known_binary_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "ico"
            | "svg"
            | "webp"
            | "bmp"
            | "tiff"
            | "pdf"
            | "zip"
            | "tar"
            | "gz"
            | "bz2"
            | "xz"
            | "7z"
            | "woff"
            | "woff2"
            | "ttf"
            | "eot"
            | "otf"
            | "mp4"
            | "webm"
            | "mp3"
            | "wav"
            | "ogg"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "bin"
            | "vsix"
            | "lock"
    )
}

fn is_minified_filename(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.ends_with(".min.js")
        || name.ends_with(".min.css")
        || name.ends_with(".bundle.js")
        || name.ends_with(".chunk.js")
}

/// Decodes UTF-8, UTF-8 BOM, UTF-16 LE/BE BOM, or lossy UTF-8; detects binary content.
fn decode_buffer_text(buffer: &[u8]) -> (bool, String) {
    if buffer.starts_with(&[0xFF, 0xFE]) {
        // UTF-16 LE BOM
        let units: Vec<u16> = buffer[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return (false, String::from_utf16_lossy(&units));
    }
    if buffer.starts_with(&[0xFE, 0xFF]) {
        // UTF-16 BE BOM
        let units: Vec<u16> = buffer[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return (false, String::from_utf16_lossy(&units));
    }
    let slice = buffer.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(buffer);

    let sample = &slice[..slice.len().min(4096)];
    let nul_found = sample.contains(&0);
    let control_count = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    let is_binary = nul_found || (!sample.is_empty() && control_count * 10 > sample.len());

    let text = match std::str::from_utf8(slice) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(slice).to_string(),
    };
    (is_binary, text)
}

fn stable_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    digest
        .iter()
        .take(6)
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn window_redacted_snippet(sanitized: &str, max_chars: usize) -> String {
    let trimmed = sanitized.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    if let Some(pos) = trimmed.find("[REDACTED") {
        let prefix_chars: Vec<char> = trimmed[..pos].chars().collect();
        let start_char = prefix_chars.len().saturating_sub(32);
        let before: String = prefix_chars[start_char..].iter().collect();
        let after: String = trimmed[pos..]
            .chars()
            .take(max_chars.saturating_sub(32))
            .collect();
        return format!("...{}{}...", before, after);
    }
    let head: String = trimmed.chars().take(max_chars).collect();
    format!("{}...", head)
}

#[derive(Default)]
struct ScanState {
    stats: ScanStats,
    findings: Vec<ScanFinding>,
    seen_keys: HashSet<String>,
    skipped_details: Vec<String>,
}

fn scan_single_file(
    path: &Path,
    engine: &SecretGuardEngine,
    opts: &ScanOptions,
    state: &mut ScanState,
) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            state.stats.vanished_files_skipped += 1;
            if opts.verbose {
                state
                    .skipped_details
                    .push(format!("vanished: {}", path.display()));
            }
            return;
        }
        Err(e) => {
            state.stats.errors_encountered += 1;
            if !opts.json_mode && !opts.quiet {
                eprintln!("❌ Failed to open '{}': {}", path.display(), e);
            }
            return;
        }
    };

    if !opts.all_files {
        if let Ok(meta) = file.metadata() {
            if meta.len() > opts.max_file_size {
                state.stats.large_files_skipped += 1;
                if opts.verbose {
                    state.skipped_details.push(format!(
                        "large ({} bytes > {}): {}",
                        meta.len(),
                        opts.max_file_size,
                        path.display()
                    ));
                }
                return;
            }
        }
    }

    let mut buffer = Vec::new();
    let read_res = if opts.all_files {
        file.read_to_end(&mut buffer)
    } else {
        file.take(opts.max_file_size.saturating_add(1))
            .read_to_end(&mut buffer)
    };
    if let Err(e) = read_res {
        state.stats.errors_encountered += 1;
        if !opts.json_mode && !opts.quiet {
            eprintln!("❌ Failed to read '{}': {}", path.display(), e);
        }
        return;
    }

    if !opts.all_files && (buffer.len() as u64) > opts.max_file_size {
        state.stats.large_files_skipped += 1;
        if opts.verbose {
            state.skipped_details.push(format!(
                "large ({} bytes > {}): {}",
                buffer.len(),
                opts.max_file_size,
                path.display()
            ));
        }
        return;
    }

    let (is_binary, text) = decode_buffer_text(&buffer);
    if is_binary && !opts.all_files {
        state.stats.binary_files_skipped += 1;
        if opts.verbose {
            state
                .skipped_details
                .push(format!("binary content: {}", path.display()));
        }
        return;
    }

    state.stats.files_scanned += 1;
    let file_display = path.display().to_string();
    let minified_file = is_minified_filename(path);

    for (idx, line) in text.lines().enumerate() {
        state.stats.lines_scanned += 1;
        let line_no = idx + 1;
        let is_minified_line = minified_file || line.len() > MINIFIED_LINE_THRESHOLD;

        let res = engine.scan_and_sanitize(line);
        if !res.has_secret {
            continue;
        }

        // On minified JS/CSS lines, suppress noisy Tier-2 contextual entropy unless high-confidence provider patterns matched
        let relevant_matches: Vec<FindingMatch> = res
            .findings
            .into_iter()
            .filter(|f| {
                !(is_minified_line && f.rule_id == "SG100" && f.confidence != Confidence::High)
            })
            .collect();

        if relevant_matches.is_empty() {
            continue;
        }

        let snippet = window_redacted_snippet(&res.sanitized_text, 140);
        for m in relevant_matches {
            let dedup_key = format!(
                "{}|{}|{}|{}|{}",
                file_display, line_no, m.rule_id, m.start, m.end
            );
            if !state.seen_keys.insert(dedup_key) {
                continue;
            }
            let fid = stable_id(&[&file_display, &line_no.to_string(), &m.rule_id, &snippet]);
            state.stats.leaks_found += 1;
            state.findings.push(ScanFinding {
                finding_id: fid,
                file: file_display.clone(),
                line: line_no,
                rule_id: m.rule_id,
                rule_name: m.rule_name,
                severity: m.severity,
                confidence: m.confidence,
                reason: m.reason,
                redacted_snippet: snippet.clone(),
            });
        }
    }
}

fn scan_dir_recursive(
    dir: &Path,
    engine: &SecretGuardEngine,
    opts: &ScanOptions,
    ignores: &[String],
    state: &mut ScanState,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            state.stats.errors_encountered += 1;
            if !opts.json_mode && !opts.quiet {
                eprintln!("❌ Error reading directory '{}': {}", dir.display(), e);
            }
            return;
        }
    };

    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                state.stats.errors_encountered += 1;
                if !opts.json_mode && !opts.quiet {
                    eprintln!(
                        "❌ Error reading directory entry in '{}': {}",
                        dir.display(),
                        e
                    );
                }
                continue;
            }
        };

        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if name == ".git" {
            state.stats.files_ignored += 1;
            if opts.verbose {
                state
                    .skipped_details
                    .push(format!(".git metadata: {}", p.display()));
            }
            continue;
        }

        let explicitly_included =
            !opts.includes.is_empty() && matches_pattern_list(&p, &name, &opts.includes);
        let explicitly_excluded =
            !opts.excludes.is_empty() && matches_pattern_list(&p, &name, &opts.excludes);

        if explicitly_excluded
            || (!explicitly_included && !opts.all_files && matches_pattern_list(&p, &name, ignores))
        {
            state.stats.files_ignored += 1;
            if opts.verbose {
                state
                    .skipped_details
                    .push(format!("excluded: {}", p.display()));
            }
            continue;
        }

        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                state.stats.vanished_files_skipped += 1;
                continue;
            }
            Err(e) => {
                state.stats.errors_encountered += 1;
                if !opts.json_mode && !opts.quiet {
                    eprintln!("❌ Error inspecting metadata for '{}': {}", p.display(), e);
                }
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            state.stats.symlinks_skipped += 1;
            if opts.verbose {
                state
                    .skipped_details
                    .push(format!("symlink: {}", p.display()));
            }
            continue;
        }

        if meta.is_dir() {
            scan_dir_recursive(&p, engine, opts, ignores, state);
        } else if meta.is_file() {
            if !opts.all_files && !explicitly_included && is_known_binary_extension(&p) {
                state.stats.binary_files_skipped += 1;
                if opts.verbose {
                    state
                        .skipped_details
                        .push(format!("binary extension: {}", p.display()));
                }
                continue;
            }
            if !opts.all_files && meta.len() > opts.max_file_size {
                state.stats.large_files_skipped += 1;
                if opts.verbose {
                    state.skipped_details.push(format!(
                        "large ({} bytes > {}): {}",
                        meta.len(),
                        opts.max_file_size,
                        p.display()
                    ));
                }
                continue;
            }

            scan_single_file(&p, engine, opts, state);
        }
    }
}

fn group_findings(findings: &[ScanFinding]) -> Vec<FindingGroup> {
    let mut map: BTreeMap<(String, String), FindingGroup> = BTreeMap::new();
    for f in findings {
        let key = (f.file.clone(), f.rule_id.clone());
        let entry = map.entry(key).or_insert_with(|| FindingGroup {
            group_id: stable_id(&[&f.file, &f.rule_id]),
            file: f.file.clone(),
            rule_id: f.rule_id.clone(),
            rule_name: f.rule_name.clone(),
            severity: f.severity,
            confidence: f.confidence,
            reason: f.reason.clone(),
            occurrences: 0,
            lines: Vec::new(),
            sample_redacted: f.redacted_snippet.clone(),
        });
        entry.occurrences += 1;
        if !entry.lines.contains(&f.line) {
            entry.lines.push(f.line);
        }
        if f.severity > entry.severity {
            entry.severity = f.severity;
        }
        if f.confidence > entry.confidence {
            entry.confidence = f.confidence;
        }
    }
    map.into_values().collect()
}

pub fn execute_scan(engine: &SecretGuardEngine, opts: &ScanOptions) -> Result<ScanReport, String> {
    let start_scan = std::time::Instant::now();
    let ignores = load_ignore_patterns(&opts.excludes);
    let mut state = ScanState::default();

    if opts.target.is_file() {
        scan_single_file(&opts.target, engine, opts, &mut state);
    } else if opts.target.is_dir() {
        scan_dir_recursive(&opts.target, engine, opts, &ignores, &mut state);
    } else {
        return Err(format!(
            "Target path '{}' does not exist.",
            opts.target.display()
        ));
    }

    let groups = group_findings(&state.findings);
    state.stats.unique_groups = groups.len();
    let elapsed = start_scan.elapsed();
    let status = if state.stats.errors_encountered > 0 {
        "incomplete".to_string()
    } else if state.stats.leaks_found > 0 {
        "findings".to_string()
    } else {
        "clean".to_string()
    };

    Ok(ScanReport {
        target: opts.target.display().to_string(),
        status: status.clone(),
        clean: state.stats.leaks_found == 0 && state.stats.errors_encountered == 0,
        stats: state.stats,
        findings: state.findings,
        groups,
        skipped_details: state.skipped_details,
        scan_duration_ms: elapsed.as_millis(),
    })
}

pub fn render_report_and_exit_code(report: &ScanReport, opts: &ScanOptions) -> i32 {
    if opts.json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
        );
        return if report.stats.errors_encountered > 0 {
            2
        } else if report.stats.leaks_found > 0 {
            1
        } else {
            0
        };
    }

    if !opts.quiet {
        let display_limit = if opts.max_findings == 0 {
            report.groups.len()
        } else {
            opts.max_findings.min(report.groups.len())
        };

        for group in report.groups.iter().take(display_limit) {
            let lines_str: Vec<String> =
                group.lines.iter().take(10).map(|l| l.to_string()).collect();
            let lines_suffix = if group.lines.len() > 10 {
                format!("{}, ...", lines_str.join(", "))
            } else {
                lines_str.join(", ")
            };

            if opts.compact {
                println!(
                    "[{}] {:?}/{:?} {} ({}) lines=[{}] count={} :: {}",
                    group.rule_id,
                    group.severity,
                    group.confidence,
                    group.file,
                    group.rule_name,
                    lines_suffix,
                    group.occurrences,
                    group.sample_redacted
                );
            } else {
                println!(
                    "⚠️  [{} | {:?} Severity | {:?} Confidence] {}:{} ({}) [{}x]\n   Reason:   {}\n   Redacted: {}\n",
                    group.rule_id,
                    group.severity,
                    group.confidence,
                    group.file,
                    lines_suffix,
                    group.rule_name,
                    group.occurrences,
                    group.reason,
                    group.sample_redacted
                );
            }
        }

        if report.groups.len() > display_limit {
            println!(
                "... {} more finding group(s) omitted (use --max-findings 0 or --json to view all)\n",
                report.groups.len() - display_limit
            );
        }

        if opts.verbose && !report.skipped_details.is_empty() {
            println!("Skipped items ({}):", report.skipped_details.len());
            for item in report.skipped_details.iter().take(50) {
                println!("  • {}", item);
            }
            if report.skipped_details.len() > 50 {
                println!("  • ... and {} more", report.skipped_details.len() - 50);
            }
            println!();
        }

        println!("────────────────────────────────────────────");
        println!("Files Scanned:       {}", report.stats.files_scanned);
        println!("Lines Scanned:       {}", report.stats.lines_scanned);
        if report.stats.files_ignored > 0 {
            println!(
                "Files Ignored:       {} (exclude / .secretguardignore / .git)",
                report.stats.files_ignored
            );
        }
        if report.stats.binary_files_skipped > 0 {
            println!(
                "Binary Files Skipped:{} (media/binary formats)",
                report.stats.binary_files_skipped
            );
        }
        if report.stats.large_files_skipped > 0 {
            println!(
                "Large Files Skipped: {} (> {} bytes; override with --max-file-size or --all-files)",
                report.stats.large_files_skipped, opts.max_file_size
            );
        }
        if report.stats.symlinks_skipped > 0 {
            println!(
                "Symlinks Skipped:    {} (unfollowed)",
                report.stats.symlinks_skipped
            );
        }
        if report.stats.vanished_files_skipped > 0 {
            println!(
                "Vanished Files:      {} (changed during scan)",
                report.stats.vanished_files_skipped
            );
        }
        if report.stats.errors_encountered > 0 {
            println!(
                "Scan Errors:         {} (uninspected)",
                report.stats.errors_encountered
            );
        }
        println!(
            "Scan Status:         {}",
            match report.status.as_str() {
                "clean" => "✅ Clean (Zero unmasked credentials detected)",
                "findings" => "🚨 Findings (Exposed credentials detected)",
                _ => "⚠️ Incomplete (Encountered read or permission errors)",
            }
        );
        println!("Execution Time:      {} ms", report.scan_duration_ms);
    }

    if report.stats.errors_encountered > 0 {
        if !opts.quiet && !opts.json_mode {
            eprintln!(
                "🚨 Scan incomplete: Encountered {} error(s) during inspection ({} findings). Aborting fail-closed.",
                report.stats.errors_encountered, report.stats.leaks_found
            );
        }
        2
    } else if report.stats.leaks_found > 0 {
        if !opts.quiet && !opts.json_mode {
            println!(
                "🚨 Found {} exposed credential(s) across {} group(s)!",
                report.stats.leaks_found, report.stats.unique_groups
            );
        }
        1
    } else {
        if !opts.quiet && !opts.json_mode {
            println!("✅ Clean! Zero unmasked secrets found across codebase.");
        }
        0
    }
}
