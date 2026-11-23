use regex::Regex;
use std::collections::HashMap;

/// Calculates the Shannon Entropy of a string: H(S) = - sum(p * log2(p))
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = HashMap::new();
    let total_len = s.chars().count() as f64;

    for ch in s.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = (count as f64) / total_len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Checks whether a given token is a known harmless identifier (e.g. standard UUID or git SHA)
fn is_known_false_positive(token: &str) -> bool {
    // Standard UUID format: 8-4-4-4-12 hex characters
    lazy_static::lazy_static! {
        static ref UUID_REGEX: Regex = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap();
        static ref GIT_HEX_REGEX: Regex = Regex::new(r"^[0-9a-f]{40}$").unwrap();
    }

    UUID_REGEX.is_match(token) || GIT_HEX_REGEX.is_match(token)
}

/// Detects high-entropy tokens inside sensitive assignment contexts (e.g., password=..., token=...)
pub fn scan_contextual_entropy(input: &str) -> Vec<(String, usize, usize)> {
    let mut detected = Vec::new();

    // Regex that catches key-value pairs or CLI flags with sensitive names
    lazy_static::lazy_static! {
        static ref SENSITIVE_CONTEXT_REGEX: Regex = Regex::new(
            r#"(?i)\b([a-zA-Z0-9_]*(?:password|passwd|secret|api_key|token|auth_token|client_secret|access_key))\b\s*[:=]\s*["']?([A-Za-z0-9_\-\./+=!@#$%^&*]{12,})["']?"#
        ).unwrap();
    }

    for cap in SENSITIVE_CONTEXT_REGEX.captures_iter(input) {
        let key_name = cap
            .get(1)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();
        if key_name.starts_with("has_")
            || key_name.starts_with("is_")
            || key_name.starts_with("no_")
        {
            continue;
        }

        if let Some(matched_val) = cap.get(2) {
            let secret_str = matched_val
                .as_str()
                .trim_end_matches(';')
                .trim_end_matches(')');

            // Ignore standard UUIDs, pure hex git SHAs, boolean expressions, or method calls
            if is_known_false_positive(secret_str)
                || secret_str.starts_with('!')
                || secret_str.contains("()")
                || secret_str.contains("::")
            {
                continue;
            }

            let entropy = calculate_shannon_entropy(secret_str);
            // High entropy threshold for passwords/tokens (typically >= 3.6 for 12+ char secrets)
            if entropy >= 3.6 {
                detected.push((
                    secret_str.to_string(),
                    matched_val.start(),
                    matched_val.end(),
                ));
            }
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = "aaaaaaaaaaaa";
        let high_entropy = "Xk9#mP$2vL@qZ8!";
        assert!(calculate_shannon_entropy(low_entropy) < 1.0);
        assert!(calculate_shannon_entropy(high_entropy) > 3.7);
    }

    #[test]
    fn test_contextual_entropy_scan() {
        let clean = "git log --pretty=format:%h";
        assert!(scan_contextual_entropy(clean).is_empty());

        let high_ent_pass = format!("Xk9#{}$2vL@{}main", "mP", "qZ8!");
        let dirty = format!("export DB_PASSWORD={}", high_ent_pass);
        let found = scan_contextual_entropy(&dirty);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, high_ent_pass);
    }
}
