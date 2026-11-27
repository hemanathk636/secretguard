use crate::{Confidence, FindingMatch, SecretGuardEngine, Severity};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB
/// Maximum staged blob size (2 MiB) allowed by `check-staged` before failing closed.
pub const DEFAULT_MAX_STAGED_BLOB_SIZE: usize = DEFAULT_MAX_FILE_SIZE as usize;
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

fn decode_utf16_bytes(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn is_ascii_text_or_ws(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t')
}

fn detect_bomless_utf16(slice: &[u8]) -> Option<bool> {
    let sample = &slice[..slice.len().min(4096)];
    let pair_count = sample.len() / 2;
    if pair_count < 4 {
        return None;
    }

    let mut even_nul = 0usize;
    let mut odd_nul = 0usize;
    let mut even_ascii = 0usize;
    let mut odd_ascii = 0usize;

    for pair in sample.chunks_exact(2) {
        if pair[0] == 0 {
            even_nul += 1;
        } else if is_ascii_text_or_ws(pair[0]) {
            even_ascii += 1;
        }
        if pair[1] == 0 {
            odd_nul += 1;
        } else if is_ascii_text_or_ws(pair[1]) {
            odd_ascii += 1;
        }
    }

    // Require >= 70% printable ASCII in one lane and >= 70% NUL in the opposite lane
    let threshold = (pair_count * 7) / 10;
    if even_ascii >= threshold && odd_nul >= threshold && odd_nul > even_nul.saturating_mul(4) {
        return Some(true); // UTF-16LE
    }
    if odd_ascii >= threshold && even_nul >= threshold && even_nul > odd_nul.saturating_mul(4) {
        return Some(false); // UTF-16BE
    }
    None
}

/// Decodes UTF-8, UTF-8 BOM, UTF-16 LE/BE (BOM or BOM-less), or lossy UTF-8; classifies binary content
/// without allowing isolated or prepended NUL bytes in text files to suppress secret scanning.
pub fn decode_buffer_text(buffer: &[u8]) -> (bool, String) {
    if buffer.starts_with(&[0xFF, 0xFE]) {
        return (false, decode_utf16_bytes(&buffer[2..], true));
    }
    if buffer.starts_with(&[0xFE, 0xFF]) {
        return (false, decode_utf16_bytes(&buffer[2..], false));
    }
    let slice = buffer.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(buffer);

    if let Some(is_le) = detect_bomless_utf16(slice) {
        return (false, decode_utf16_bytes(slice, is_le));
    }

    let sample = &slice[..slice.len().min(4096)];
    let non_nul_control_count = sample
        .iter()
        .filter(|&&b| b != 0 && b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    let nul_count = sample.iter().filter(|&&b| b == 0).count();
    let total_control_count = non_nul_control_count + nul_count;

    if !sample.is_empty() && total_control_count * 10 > sample.len() {
        // High control/NUL density (>10%): if it is solely NUL padding around clean printable text
        // (<=5% non-NUL control bytes, >=90% printable/UTF-8, valid UTF-8), scan it rather than
        // allowing NUL padding to suppress secret detection. Genuine binary blobs fail this check.
        let non_nul_sample: Vec<u8> = slice
            .iter()
            .copied()
            .filter(|&b| b != 0)
            .take(4096)
            .collect();
        if non_nul_sample.is_empty() {
            return (true, String::new());
        }
        let printable_or_utf8 = non_nul_sample
            .iter()
            .filter(|&&b| is_ascii_text_or_ws(b) || b >= 0x80)
            .count();
        let non_nul_ctrl = non_nul_sample
            .iter()
            .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
            .count();
        let has_invalid_utf8 = match std::str::from_utf8(&non_nul_sample) {
            Ok(_) => false,
            Err(e) => e.error_len().is_some(),
        };
        if non_nul_ctrl * 20 > non_nul_sample.len()
            || printable_or_utf8 * 100 < non_nul_sample.len() * 90
            || has_invalid_utf8
        {
            return (true, String::new());
        }
    }

    let mut text = match std::str::from_utf8(slice) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(slice).to_string(),
    };
    if text.contains('\0') {
        text = text.replace('\0', "");
    }
    (false, text)
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

/// Explicit, unique ownership marker embedded in managed SecretGuard pre-commit hooks.
pub const PRE_COMMIT_HOOK_MARKER: &str = "# secretguard-managed-hook: pre-commit";

/// Fail-closed POSIX sh pre-commit hook installed by `install-pre-commit` and `SetupWizard`.
pub const PRE_COMMIT_HOOK_SCRIPT: &str = r#"#!/bin/sh
# secretguard-managed-hook: pre-commit
# SecretGuard Git Pre-Commit Hook (Sub-millisecond Secret Interceptor)
# https://github.com/hemanathk636/secretguard

if ! command -v secretguard >/dev/null 2>&1; then
    echo "" >&2
    echo "\033[1;31m✖ [SecretGuard] Git commit blocked: 'secretguard' binary not found in PATH!\033[0m" >&2
    echo "Install SecretGuard or restore PATH before committing. (Use 'git commit --no-verify' to bypass if intentional)" >&2
    echo "" >&2
    exit 1
fi

SCAN_ERR=$(secretguard check-staged 2>&1)
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "" >&2
    echo "\033[1;31m✖ [SecretGuard] Git commit blocked: Staged blob scan failed or secret detected!\033[0m" >&2
    if [ -n "$SCAN_ERR" ]; then
        echo "\033[0;33m$SCAN_ERR\033[0m" >&2
    fi
    echo "Please redact credentials or fix scanner errors before committing. (Use 'git commit --no-verify' to bypass if intentional)" >&2
    echo "" >&2
    exit 1
fi
exit 0
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookInstallOutcome {
    Installed,
    Upgraded,
    AlreadyCurrent,
}

fn set_hook_executable_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_file() {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Returns true only for hooks generated by SecretGuard (explicit marker or exact legacy templates),
/// preserving user-customized hooks even if they mention or invoke `secretguard`.
pub fn is_secretguard_managed_hook(content: &str) -> bool {
    let normalized = content.replace("\r\n", "\n");
    let trimmed = normalized.trim_start_matches('\u{feff}');

    // Current / v2 marker-owned hooks
    if trimmed.starts_with("#!/bin/sh\n")
        && trimmed.lines().any(|line| line == PRE_COMMIT_HOOK_MARKER)
        && trimmed.contains("secretguard check-staged")
    {
        return true;
    }

    // Legacy `install-pre-commit` hook (v1.0.0)
    let is_legacy_main = trimmed.starts_with("#!/bin/sh\n")
        && trimmed
            .contains("# SecretGuard Git Pre-Commit Hook (Sub-millisecond Secret Interceptor)")
        && trimmed.contains("# https://github.com/hemanathk636/secretguard")
        && trimmed.contains("STAGED_DIFF=$(git diff --cached --unified=0")
        && trimmed.contains("| secretguard check");

    // Legacy `SetupWizard` hook (v1.0.0)
    let is_legacy_init = trimmed
        .starts_with("#!/bin/sh\nif command -v secretguard >/dev/null 2>&1; then\n")
        && trimmed.contains("DIFF=$(git diff --cached --unified=0")
        && trimmed.contains("Blocked commit: Leaked API key or secret in staged diff!");

    is_legacy_main || is_legacy_init
}

fn write_hook_atomically(pre_commit_path: &Path, content: &str) -> Result<(), String> {
    use std::io::Write;

    let parent = pre_commit_path
        .parent()
        .ok_or_else(|| "Invalid pre-commit hook path: missing parent directory".to_string())?;
    let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| {
        format!(
            "Failed to inspect hooks directory '{}': {}",
            parent.display(),
            e
        )
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err(format!(
            "Refusing to install hook inside non-directory or symlink '{}'",
            parent.display()
        ));
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(
        ".secretguard-pre-commit.tmp.{}.{}",
        std::process::id(),
        nanos
    ));

    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| {
            format!(
                "Failed to create temporary hook file '{}': {}",
                tmp_path.display(),
                e
            )
        })?;

    if let Err(e) = tmp_file
        .write_all(content.as_bytes())
        .and_then(|_| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("Failed to write temporary hook file: {}", e));
    }
    drop(tmp_file);

    set_hook_executable_permissions(&tmp_path);

    if let Err(err) = crate::vault::atomic_replace_file(&tmp_path, pre_commit_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    set_hook_executable_permissions(pre_commit_path);
    Ok(())
}

/// Installs or safely upgrades a SecretGuard pre-commit hook without following symlinks or overwriting custom hooks unless `force` is true.
pub fn install_or_upgrade_pre_commit_hook(
    pre_commit_path: &Path,
    force: bool,
) -> Result<HookInstallOutcome, String> {
    match std::fs::symlink_metadata(pre_commit_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to overwrite symlink pre-commit hook at '{}'.",
                    pre_commit_path.display()
                ));
            }
            if !meta.file_type().is_file() {
                return Err(format!(
                    "Refusing to overwrite non-regular filesystem object at '{}'.",
                    pre_commit_path.display()
                ));
            }

            let existing = std::fs::read_to_string(pre_commit_path).map_err(|_| {
                format!(
                    "Existing non-SecretGuard pre-commit hook at '{}' was preserved. Re-run with --force to replace it.",
                    pre_commit_path.display()
                )
            })?;

            if existing == PRE_COMMIT_HOOK_SCRIPT {
                set_hook_executable_permissions(pre_commit_path);
                return Ok(HookInstallOutcome::AlreadyCurrent);
            }

            if !is_secretguard_managed_hook(&existing) && !force {
                return Err(format!(
                    "Existing non-SecretGuard pre-commit hook at '{}' was preserved. Re-run with --force to replace it.",
                    pre_commit_path.display()
                ));
            }

            write_hook_atomically(pre_commit_path, PRE_COMMIT_HOOK_SCRIPT)?;
            Ok(HookInstallOutcome::Upgraded)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_hook_atomically(pre_commit_path, PRE_COMMIT_HOOK_SCRIPT)?;
            Ok(HookInstallOutcome::Installed)
        }
        Err(e) => Err(format!(
            "Failed to inspect pre-commit hook at '{}': {}",
            pre_commit_path.display(),
            e
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEntry {
    pub new_mode: String,
    pub new_oid: String,
    pub status: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFinding {
    pub path: String,
    pub matched_rules: Vec<String>,
}

/// Parses `git diff --cached --raw -z --no-ext-diff` output into staged entries.
/// Fails closed if any record is malformed or truncated.
pub fn parse_git_diff_raw_z(raw: &[u8]) -> Result<Vec<StagedEntry>, String> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < raw.len() {
        let Some(rel_nul) = raw[pos..].iter().position(|&b| b == 0) else {
            return Err("Malformed git diff --raw -z record: missing header NUL".to_string());
        };
        let header_bytes = &raw[pos..pos + rel_nul];
        pos += rel_nul + 1;

        let header = std::str::from_utf8(header_bytes)
            .map_err(|_| "Malformed git diff --raw -z header: invalid UTF-8".to_string())?;
        if !header.starts_with(':') {
            return Err(format!("Unexpected git diff --raw -z header: '{}'", header));
        }
        let fields: Vec<&str> = header[1..].split(' ').collect();
        if fields.len() != 5 {
            return Err(format!(
                "Unexpected git diff --raw -z field count ({}): '{}'",
                fields.len(),
                header
            ));
        }

        let new_mode = fields[1];
        let new_oid = fields[3];
        let status = fields[4];

        if new_oid.len() < 40 || !new_oid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("Invalid staged object ID '{}'", new_oid));
        }

        let Some(path_nul) = raw[pos..].iter().position(|&b| b == 0) else {
            return Err("Malformed git diff --raw -z record: missing path NUL".to_string());
        };
        let first_path = &raw[pos..pos + path_nul];
        pos += path_nul + 1;

        let target_path_bytes = if status.starts_with('R') || status.starts_with('C') {
            let Some(new_path_nul) = raw[pos..].iter().position(|&b| b == 0) else {
                return Err(
                    "Malformed git diff --raw -z rename/copy record: missing target path NUL"
                        .to_string(),
                );
            };
            let new_path = &raw[pos..pos + new_path_nul];
            pos += new_path_nul + 1;
            new_path
        } else {
            first_path
        };

        entries.push(StagedEntry {
            new_mode: new_mode.to_string(),
            new_oid: new_oid.to_string(),
            status: status.to_string(),
            path: String::from_utf8_lossy(target_path_bytes).to_string(),
        });
    }

    Ok(entries)
}

/// Scans all non-deleted staged blobs directly from Git's index without reading the working tree.
pub fn scan_staged_blobs(engine: &SecretGuardEngine) -> Result<Vec<StagedFinding>, String> {
    scan_staged_blobs_in_dir(engine, None)
}

/// Scans staged blobs in `repo_dir` (or current working directory when `None`) with `DEFAULT_MAX_STAGED_BLOB_SIZE`.
pub fn scan_staged_blobs_in_dir(
    engine: &SecretGuardEngine,
    repo_dir: Option<&Path>,
) -> Result<Vec<StagedFinding>, String> {
    scan_staged_blobs_in_dir_with_limit(engine, repo_dir, DEFAULT_MAX_STAGED_BLOB_SIZE)
}

/// Scans staged blobs in `repo_dir` using an explicit `max_blob_bytes` limit, failing closed on oversized blobs.
///
/// Note on Git index concurrency: during `git commit`, Git holds `index.lock` (or a temporary index via
/// `GIT_INDEX_FILE`) while invoking `pre-commit`, which prevents normal concurrent `git add`/`git reset`
/// index updates. However, if an external process forcibly removes `index.lock` or mutates `GIT_INDEX_FILE`
/// after `check-staged` returns and before `git commit` finalizes the tree object, a residual TOCTOU window exists.
pub fn scan_staged_blobs_in_dir_with_limit(
    engine: &SecretGuardEngine,
    repo_dir: Option<&Path>,
    max_blob_bytes: usize,
) -> Result<Vec<StagedFinding>, String> {
    let mut diff_cmd = std::process::Command::new("git");
    if let Some(dir) = repo_dir {
        diff_cmd.current_dir(dir);
    }
    let diff_out = diff_cmd
        .args([
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--full-index",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-renames",
            "--diff-filter=ACMRT",
        ])
        .output()
        .map_err(|e| format!("Failed to invoke git diff --cached: {}", e))?;

    if !diff_out.status.success() {
        let stderr = String::from_utf8_lossy(&diff_out.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("git diff --cached failed with status {}", diff_out.status)
        } else {
            format!("git diff --cached failed: {}", stderr)
        });
    }

    let entries = parse_git_diff_raw_z(&diff_out.stdout)?;
    let mut findings = Vec::new();

    for entry in entries {
        // Skip symlinks (120000) and submodule gitlinks (160000); never follow symlinks on disk.
        if entry.new_mode == "120000" || entry.new_mode == "160000" {
            continue;
        }

        let mut size_cmd = std::process::Command::new("git");
        if let Some(dir) = repo_dir {
            size_cmd.current_dir(dir);
        }
        let size_out = size_cmd
            .args(["cat-file", "-s", &entry.new_oid])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to query staged blob size for '{}': {}",
                    entry.path, e
                )
            })?;
        if !size_out.status.success() {
            let stderr = String::from_utf8_lossy(&size_out.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                format!("git cat-file -s failed for '{}'", entry.path)
            } else {
                format!("git cat-file -s failed for '{}': {}", entry.path, stderr)
            });
        }
        let blob_size: usize = String::from_utf8_lossy(&size_out.stdout)
            .trim()
            .parse()
            .map_err(|_| format!("Invalid staged blob size reported for '{}'", entry.path))?;
        if blob_size > max_blob_bytes {
            return Err(format!(
                "Staged blob '{}' size ({} bytes) exceeds maximum allowed limit ({} bytes); failing closed",
                entry.path, blob_size, max_blob_bytes
            ));
        }

        let mut blob_cmd = std::process::Command::new("git");
        if let Some(dir) = repo_dir {
            blob_cmd.current_dir(dir);
        }
        let blob_out = blob_cmd
            .args(["cat-file", "blob", &entry.new_oid])
            .output()
            .map_err(|e| format!("Failed to invoke git cat-file for '{}': {}", entry.path, e))?;

        if !blob_out.status.success() {
            let stderr = String::from_utf8_lossy(&blob_out.stderr).trim().to_string();
            return Err(if stderr.is_empty() {
                format!("git cat-file blob failed for '{}'", entry.path)
            } else {
                format!("git cat-file blob failed for '{}': {}", entry.path, stderr)
            });
        }

        if blob_out.stdout.len() > max_blob_bytes {
            return Err(format!(
                "Staged blob '{}' size ({} bytes) exceeds maximum allowed limit ({} bytes); failing closed",
                entry.path,
                blob_out.stdout.len(),
                max_blob_bytes
            ));
        }

        let (is_binary, text) = decode_buffer_text(&blob_out.stdout);
        if is_binary {
            continue;
        }

        let res = engine.scan_and_sanitize(&text);
        if res.has_secret {
            findings.push(StagedFinding {
                path: entry.path,
                matched_rules: res.matched_rules,
            });
        }
    }

    Ok(findings)
}
