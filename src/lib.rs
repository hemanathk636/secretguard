pub mod blastradius;
pub mod canary;
pub mod clipboard;
pub mod compliance;
pub mod completions;
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
}

pub struct SecretGuardEngine {
    patterns: Vec<SecretPattern>,
    whitelist: Vec<String>,
}

#[inline]
fn safe_prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

impl SecretGuardEngine {
    pub fn new() -> Self {
        let cfg = config::SecretGuardConfig::load();
        let mut patterns = get_high_confidence_patterns();

        for cp in &cfg.custom_patterns {
            if let Ok(re) = regex::Regex::new(&cp.regex) {
                patterns.push(SecretPattern {
                    name: Box::leak(cp.name.clone().into_boxed_str()),
                    description: Box::leak(cp.description.clone().unwrap_or_default().into_boxed_str()),
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
                };
            }
        }

        let mut sanitized = input.to_string();
        let mut synthetic = input.to_string();
        let mut matched_rules = Vec::new();

        // Tier 1: High-confidence structured patterns
        for p in &self.patterns {
            if p.regex.is_match(&sanitized) {
                matched_rules.push(p.name.to_string());
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
                if secret_val.chars().count() > 8 {
                    let masked = format!("{}[REDACTED]", safe_prefix(&secret_val, 3));
                    sanitized = sanitized.replace(&secret_val, &masked);
                } else {
                    sanitized = sanitized.replace(&secret_val, "[REDACTED]");
                }
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
                if !hits.is_empty() || lower.contains("password") || lower.contains("secret") || (decoded_str.contains(':') && decoded_str.len() >= 10) {
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
                sanitized = sanitized.replace(&encoded_str, &mask);
                synthetic = synthetic.replace(&encoded_str, "[SYNTHETIC_MOCK_ENCODED_TOKEN]");
            }
        }

        let has_secret = !matched_rules.is_empty();

        ScanResult {
            has_secret,
            sanitized_text: sanitized,
            synthetic_text: synthetic,
            matched_rules,
        }
    }
}

impl Default for SecretGuardEngine {
    fn default() -> Self {
        Self::new()
    }
}
