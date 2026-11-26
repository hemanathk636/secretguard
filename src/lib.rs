pub mod audit;
pub mod blastradius;
pub mod broker;
pub mod canary;
pub mod clipboard;
pub mod completions;
pub mod compliance;
pub mod config;
pub mod dashboard;
pub mod docker;
pub mod encoding;
pub mod entropy;
pub mod firewall;
pub mod ghost;
pub mod identity;
pub mod immune;
pub mod init;
pub mod ipc;
pub mod lifecycle;
pub mod mcp;
pub mod mesh;
pub mod panic;
pub mod patterns;
pub mod pii;
pub mod policy;
pub mod proxy;
pub mod radar;
pub mod scanner;
pub mod self_test;
pub mod shield;
pub mod swapper;
pub mod synthetic;
pub mod timemachine;
pub mod vault;
pub mod verifier;

use entropy::{scan_contextual_entropy, scan_contextual_entropy_detailed};
use patterns::get_high_confidence_patterns;
pub use patterns::{Confidence, SecretPattern, Severity};
use synthetic::generate_synthetic_token;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub reason: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub has_secret: bool,
    pub sanitized_text: String,
    pub synthetic_text: String,
    pub matched_rules: Vec<String>,
    pub redacted_pairs: Vec<(String, String)>,
    pub findings: Vec<FindingMatch>,
}

#[derive(Clone)]
pub struct SecretGuardEngine {
    patterns: Vec<SecretPattern>,
    whitelist: Vec<String>,
}

/// Strips standard ANSI terminal control and color sequences (e.g., \x1b[31m, \x1b[0m)
/// to prevent evasion of pattern detection via terminal styling artifacts.
pub fn strip_ansi_escapes(s: &str) -> String {
    if !s.contains('\x1b') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next();
                    while let Some(&seq_char) = chars.peek() {
                        chars.next();
                        if ('@'..='~').contains(&seq_char) || seq_char.is_ascii_alphabetic() {
                            break;
                        }
                    }
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

impl SecretGuardEngine {
    pub fn new() -> Self {
        let cfg = config::SecretGuardConfig::load();
        let mut patterns = get_high_confidence_patterns();

        for cp in &cfg.custom_patterns {
            if let Ok(re) = regex::Regex::new(&cp.regex) {
                patterns.push(SecretPattern {
                    rule_id: "SG900",
                    name: Box::leak(cp.name.clone().into_boxed_str()),
                    description: Box::leak(
                        cp.description.clone().unwrap_or_default().into_boxed_str(),
                    ),
                    severity: Severity::High,
                    regex: re,
                });
            }
        }

        Self {
            patterns,
            whitelist: cfg.whitelist,
        }
    }

    pub fn patterns_len(&self) -> usize {
        self.patterns.len()
    }

    /// Fast scan, sanitize (with redaction masks), and generate format-preserving synthetic mocks.
    pub fn scan_and_sanitize(&self, input: &str) -> ScanResult {
        // Fast-path whitelist check
        for w in &self.whitelist {
            if !w.is_empty() && (input.trim() == w || input.contains(w)) {
                return ScanResult {
                    has_secret: false,
                    sanitized_text: input.to_string(),
                    synthetic_text: input.to_string(),
                    matched_rules: Vec::new(),
                    redacted_pairs: Vec::new(),
                    findings: Vec::new(),
                };
            }
        }

        let mut sanitized = input.to_string();
        let mut synthetic = input.to_string();
        let mut matched_rules = Vec::new();
        let mut redacted_pairs = Vec::new();
        let mut findings = Vec::new();

        // Tier 1: High-confidence structured patterns
        for p in &self.patterns {
            if p.regex.is_match(&sanitized) {
                matched_rules.push(p.name.to_string());
                for m in p.regex.find_iter(&sanitized) {
                    let matched = m.as_str().to_string();
                    redacted_pairs.push((matched, "[REDACTED]".to_string()));
                    findings.push(FindingMatch {
                        rule_id: p.rule_id.to_string(),
                        rule_name: p.name.to_string(),
                        severity: p.severity,
                        confidence: Confidence::High,
                        reason: format!("Matched provider pattern: {}", p.description),
                        start: m.start(),
                        end: m.end(),
                    });
                }
                sanitized = p.regex.replace_all(&sanitized, "[REDACTED]").to_string();

                synthetic = p
                    .regex
                    .replace_all(&synthetic, |caps: &regex::Captures| {
                        let matched = &caps[0];
                        generate_synthetic_token(p.name, matched)
                    })
                    .to_string();
            }
        }

        // Tier 2: Contextual entropy (catches passwords, random JWTs, unknown tokens)
        let mut entropy_hits = scan_contextual_entropy_detailed(&sanitized);
        if !entropy_hits.is_empty() {
            matched_rules.push("Contextual Entropy Password/Token".to_string());
            // Sort descending by start byte offset so in-place range replacements don't shift earlier offsets
            entropy_hits.sort_by_key(|a| std::cmp::Reverse(a.start));
            let mut prev_start = usize::MAX;
            for hit in entropy_hits {
                if hit.end > prev_start || hit.end > sanitized.len() || hit.start > hit.end {
                    continue;
                }
                prev_start = hit.start;
                let mock_val = generate_synthetic_token("Entropy", &hit.value);
                let masked = "[REDACTED]".to_string();
                redacted_pairs.push((hit.value.clone(), masked.clone()));
                sanitized.replace_range(hit.start..hit.end, &masked);
                synthetic = synthetic.replace(&hit.value, &mock_val);
                let sev = match hit.confidence {
                    Confidence::High => Severity::High,
                    Confidence::Medium => Severity::Medium,
                    Confidence::Low => Severity::Low,
                };
                findings.push(FindingMatch {
                    rule_id: "SG100".to_string(),
                    rule_name: "Contextual Entropy Password/Token".to_string(),
                    severity: sev,
                    confidence: hit.confidence,
                    reason: hit.reason,
                    start: hit.start,
                    end: hit.end,
                });
            }
        }

        // Tier 3: In-Memory Encoded Secret Inspection (Base64 & URL percent-encoding)
        let encoded_candidates = encoding::find_encoded_candidates(input);
        for (encoded_str, decoded_str) in encoded_candidates {
            let mut detected_rule = None;
            let mut detected_conf = Confidence::Medium;
            for p in &self.patterns {
                if p.regex.is_match(&decoded_str) {
                    detected_rule = Some(format!("Encoded ({})", p.name));
                    detected_conf = Confidence::High;
                    break;
                }
            }

            // Also check if decoded string contains contextual entropy or high-risk password/token
            if detected_rule.is_none() {
                let hits = scan_contextual_entropy(&decoded_str);
                let lower = decoded_str.to_lowercase();
                let is_basic_auth = if let Some((user, pass)) = decoded_str.split_once(':') {
                    !user.is_empty()
                        && !pass.is_empty()
                        && !user.contains(char::is_whitespace)
                        && !pass.contains(char::is_whitespace)
                        && !user.contains('/')
                        && !user.contains('<')
                        && (pass.len() >= 6 || !scan_contextual_entropy(pass).is_empty())
                        && (lower.contains("pass")
                            || lower.contains("secret")
                            || input.to_lowercase().contains("basic")
                            || input.to_lowercase().contains("auth"))
                } else {
                    false
                };

                if !hits.is_empty()
                    || lower.contains("password=")
                    || lower.contains("secret=")
                    || is_basic_auth
                {
                    detected_rule = Some("Encoded (Credential/Token)".to_string());
                }
            }

            if let Some(rule) = detected_rule {
                matched_rules.push(rule.clone());
                let mask = "[REDACTED_ENCODED_SECRET]".to_string();
                let start = input.find(&encoded_str).unwrap_or(0);
                let end = start + encoded_str.len();
                redacted_pairs.push((encoded_str.clone(), mask.clone()));
                sanitized = sanitized.replace(&encoded_str, &mask);
                synthetic = synthetic.replace(&encoded_str, "[SYNTHETIC_MOCK_ENCODED_TOKEN]");
                findings.push(FindingMatch {
                    rule_id: "SG200".to_string(),
                    rule_name: rule,
                    severity: Severity::High,
                    confidence: detected_conf,
                    reason: "Encoded payload decoded to credential pattern or high-entropy secret"
                        .to_string(),
                    start,
                    end,
                });
            }
        }

        // Tier 4: ANSI Terminal Escape Sequence Evasion Inspection
        if input.contains('\x1b') {
            let stripped_ansi = strip_ansi_escapes(input);
            for p in &self.patterns {
                if p.regex.is_match(&stripped_ansi)
                    && !matched_rules.iter().any(|r| r.contains(p.name))
                {
                    let rule_name = format!("ANSI-Obfuscated ({})", p.name);
                    matched_rules.push(rule_name.clone());
                    sanitized = "[REDACTED_ANSI_SECRET]".to_string();
                    synthetic = "[SYNTHETIC_MOCK_ANSI_TOKEN]".to_string();
                    findings.push(FindingMatch {
                        rule_id: "SG300".to_string(),
                        rule_name,
                        severity: Severity::High,
                        confidence: Confidence::High,
                        reason: "ANSI escape sequence obfuscating structured credential"
                            .to_string(),
                        start: 0,
                        end: input.len(),
                    });
                    break;
                }
            }
        }

        let has_secret = !matched_rules.is_empty();

        ScanResult {
            has_secret,
            sanitized_text: sanitized,
            synthetic_text: synthetic,
            matched_rules,
            redacted_pairs,
            findings,
        }
    }
}

impl Default for SecretGuardEngine {
    fn default() -> Self {
        Self::new()
    }
}
