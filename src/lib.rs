pub mod blastradius;
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
pub mod immune;
pub mod init;
pub mod mcp;
pub mod mesh;
pub mod panic;
pub mod patterns;
pub mod pii;
pub mod proxy;
pub mod radar;
pub mod shield;
pub mod swapper;
pub mod synthetic;
pub mod timemachine;
pub mod vault;
pub mod verifier;

use entropy::scan_contextual_entropy;
use patterns::{get_high_confidence_patterns, SecretPattern};
use synthetic::generate_synthetic_token;

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub has_secret: bool,
    pub sanitized_text: String,
    pub synthetic_text: String,
    pub matched_rules: Vec<String>,
    pub redacted_pairs: Vec<(String, String)>,
}

pub struct SecretGuardEngine {
    patterns: Vec<SecretPattern>,
    whitelist: Vec<String>,
}

#[inline]
fn safe_prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
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
                        if (seq_char >= '@' && seq_char <= '~') || seq_char.is_ascii_alphabetic() {
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
                    name: Box::leak(cp.name.clone().into_boxed_str()),
                    description: Box::leak(
                        cp.description.clone().unwrap_or_default().into_boxed_str(),
                    ),
                    regex: re,
                });
            }
        }

        Self {
            patterns,
            whitelist: cfg.whitelist,
        }
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
                };
            }
        }

        let mut sanitized = input.to_string();
        let mut synthetic = input.to_string();
        let mut matched_rules = Vec::new();
        let mut redacted_pairs = Vec::new();

        // Tier 1: High-confidence structured patterns
        for p in &self.patterns {
            if p.regex.is_match(&sanitized) {
                matched_rules.push(p.name.to_string());
                for caps in p.regex.captures_iter(&sanitized) {
                    let matched = caps[0].to_string();
                    let replacement = if matched.chars().count() > 10 {
                        format!("{}[REDACTED]", safe_prefix(&matched, 4))
                    } else {
                        "[REDACTED]".to_string()
                    };
                    redacted_pairs.push((matched, replacement));
                }
                sanitized = p
                    .regex
                    .replace_all(&sanitized, |caps: &regex::Captures| {
                        let matched = &caps[0];
                        if matched.chars().count() > 10 {
                            format!("{}[REDACTED]", safe_prefix(matched, 4))
                        } else {
                            "[REDACTED]".to_string()
                        }
                    })
                    .to_string();

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
        let entropy_hits = scan_contextual_entropy(&sanitized);
        if !entropy_hits.is_empty() {
            matched_rules.push("Contextual Entropy Password/Token".to_string());
            for (secret_val, _, _) in entropy_hits {
                let mock_val = generate_synthetic_token("Entropy", &secret_val);
                let masked = if secret_val.chars().count() > 8 {
                    format!("{}[REDACTED]", safe_prefix(&secret_val, 3))
                } else {
                    "[REDACTED]".to_string()
                };
                redacted_pairs.push((secret_val.clone(), masked.clone()));
                sanitized = sanitized.replace(&secret_val, &masked);
                synthetic = synthetic.replace(&secret_val, &mock_val);
            }
        }

        // Tier 3: In-Memory Encoded Secret Inspection (Base64 & URL percent-encoding)
        let encoded_candidates = encoding::find_encoded_candidates(input);
        for (encoded_str, decoded_str) in encoded_candidates {
            let mut detected_rule = None;
            for p in &self.patterns {
                if p.regex.is_match(&decoded_str) {
                    detected_rule = Some(format!("Encoded ({})", p.name));
                    break;
                }
            }

            // Also check if decoded string contains contextual entropy or high-risk password/token
            if detected_rule.is_none() {
                let hits = scan_contextual_entropy(&decoded_str);
                let lower = decoded_str.to_lowercase();
                if !hits.is_empty()
                    || lower.contains("password")
                    || lower.contains("secret")
                    || (decoded_str.contains(':') && decoded_str.len() >= 10)
                {
                    detected_rule = Some("Encoded (Credential/Token)".to_string());
                }
            }

            if let Some(rule) = detected_rule {
                matched_rules.push(rule);
                let mask = if encoded_str.chars().count() > 10 {
                    format!("{}[REDACTED_ENCODED_SECRET]", safe_prefix(&encoded_str, 4))
                } else {
                    "[REDACTED_ENCODED_SECRET]".to_string()
                };
                redacted_pairs.push((encoded_str.clone(), mask.clone()));
                sanitized = sanitized.replace(&encoded_str, &mask);
                synthetic = synthetic.replace(&encoded_str, "[SYNTHETIC_MOCK_ENCODED_TOKEN]");
            }
        }

        // Tier 4: ANSI Terminal Escape Sequence Evasion Inspection
        if input.contains('\x1b') {
            let stripped_ansi = strip_ansi_escapes(input);
            for p in &self.patterns {
                if p.regex.is_match(&stripped_ansi)
                    && !matched_rules.iter().any(|r| r.contains(p.name))
                {
                    matched_rules.push(format!("ANSI-Obfuscated ({})", p.name));
                    sanitized = "[REDACTED_ANSI_SECRET]".to_string();
                    synthetic = "[SYNTHETIC_MOCK_ANSI_TOKEN]".to_string();
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
        }
    }
}

impl Default for SecretGuardEngine {
    fn default() -> Self {
        Self::new()
    }
}
