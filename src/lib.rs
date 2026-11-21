pub mod blastradius;
pub mod canary;
pub mod clipboard;
pub mod compliance;
pub mod docker;
pub mod entropy;
pub mod firewall;
pub mod mcp;
pub mod mesh;
pub mod panic;
pub mod patterns;
pub mod pii;
pub mod proxy;
pub mod radar;
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
}

impl SecretGuardEngine {
    pub fn new() -> Self {
        Self {
            patterns: get_high_confidence_patterns(),
        }
    }

    /// Fast scan, sanitize (with redaction masks), and generate format-preserving synthetic mocks.
    pub fn scan_and_sanitize(&self, input: &str) -> ScanResult {
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
                        if matched.len() > 10 {
                            format!("{}[REDACTED]", &matched[..4])
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
                if secret_val.len() > 8 {
                    let masked = format!("{}[REDACTED]", &secret_val[..3]);
                    sanitized = sanitized.replace(&secret_val, &masked);
                } else {
                    sanitized = sanitized.replace(&secret_val, "[REDACTED]");
                }
                synthetic = synthetic.replace(&secret_val, &mock_val);
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
