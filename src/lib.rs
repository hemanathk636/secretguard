pub mod entropy;
pub mod patterns;

use entropy::scan_contextual_entropy;
use patterns::{get_high_confidence_patterns, SecretPattern};

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub has_secret: bool,
    pub sanitized_text: String,
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

    /// Fast scan and sanitize. Runs Tier 1 (Regex) + Tier 2 (Entropy)
    pub fn scan_and_sanitize(&self, input: &str) -> ScanResult {
        let mut sanitized = input.to_string();
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
            }
        }

        // Tier 2: Contextual entropy (catches passwords, random JWTs, unknown tokens)
        let entropy_hits = scan_contextual_entropy(&sanitized);
        if !entropy_hits.is_empty() {
            matched_rules.push("Contextual Entropy Password/Token".to_string());
            for (secret_val, _, _) in entropy_hits {
                if secret_val.len() > 8 {
                    let masked = format!("{}[REDACTED]", &secret_val[..3]);
                    sanitized = sanitized.replace(&secret_val, &masked);
                } else {
                    sanitized = sanitized.replace(&secret_val, "[REDACTED]");
                }
            }
        }

        let has_secret = !matched_rules.is_empty();

        ScanResult {
            has_secret,
            sanitized_text: sanitized,
            matched_rules,
        }
    }
}

impl Default for SecretGuardEngine {
    fn default() -> Self {
        Self::new()
    }
}
