use crate::patterns::Confidence;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ContextualEntropyHit {
    pub value: String,
    pub start: usize,
    pub end: usize,
    pub confidence: Confidence,
    pub reason: String,
}

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

fn is_non_secret_key_name(key_lower: &str) -> bool {
    if key_lower.starts_with("has_")
        || key_lower.starts_with("is_")
        || key_lower.starts_with("no_")
        || key_lower.starts_with("enable_")
        || key_lower.starts_with("allow_")
        || key_lower.starts_with("use_")
        || key_lower.starts_with("show_")
        || key_lower.starts_with("with_")
    {
        return true;
    }

    matches!(
        key_lower,
        "progresstoken"
            | "progress_token"
            | "nextpagetoken"
            | "next_page_token"
            | "pagetoken"
            | "page_token"
            | "continuationtoken"
            | "continuation_token"
            | "synctoken"
            | "sync_token"
            | "cursortoken"
            | "cursor_token"
            | "cancellationtoken"
            | "cancellation_token"
    )
}

fn is_placeholder_value(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.contains("[REDACTED") || trimmed.contains("[SYNTHETIC_MOCK") {
        return true;
    }
    if trimmed.starts_with("${")
        || trimmed.starts_with("{{")
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
    {
        return true;
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("YOUR_")
        || upper.starts_with("REPLACE_")
        || upper.starts_with("INSERT_")
        || upper.starts_with("ENTER_")
        || upper.starts_with("EXAMPLE_")
        || upper.starts_with("DUMMY_")
        || upper.starts_with("MOCK_")
        || upper.starts_with("FAKE_")
        || upper.starts_with("PLACEHOLDER")
        || upper.starts_with("CHANGEME")
        || upper.ends_with("_HERE")
        || upper == "SECRET"
        || upper == "PASSWORD"
        || upper == "TOKEN"
        || upper == "API_KEY"
    {
        return true;
    }

    // Repeated single character (e.g., "xxxxxxxxxxxx", "000000000000")
    let mut chars = trimmed.chars();
    if let Some(first) = chars.next() {
        if chars.all(|c| c == first) {
            return true;
        }
    }

    false
}

fn is_dotted_identifier_chain(val: &str) -> bool {
    if !val.contains('.') {
        return false;
    }
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let all_ident = parts.iter().all(|p| {
        !p.is_empty()
            && p.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if !all_ident {
        return false;
    }
    // Check if any segment looks like a random secret vs normal code identifier
    let has_digits_in_last = parts
        .last()
        .is_some_and(|p| p.chars().any(|c| c.is_ascii_digit()));
    let known_code_root = matches!(
        parts[0].to_ascii_lowercase().as_str(),
        "req"
            | "res"
            | "ctx"
            | "auth_ctx"
            | "process"
            | "env"
            | "this"
            | "self"
            | "props"
            | "config"
            | "options"
            | "params"
            | "data"
            | "user"
            | "meeting"
            | "event"
            | "window"
            | "document"
            | "os"
            | "app"
            | "client"
            | "server"
            | "response"
            | "request"
    );
    known_code_root || !has_digits_in_last
}

/// Checks whether a given token is a known harmless identifier (e.g. standard UUID, git SHA, code expression, or placeholder)
fn is_known_false_positive(token: &str, was_quoted: bool) -> bool {
    lazy_static::lazy_static! {
        static ref UUID_REGEX: Regex = Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap();
        static ref GIT_HEX_REGEX: Regex = Regex::new(r"^[0-9a-f]{40}$").unwrap();
    }

    if UUID_REGEX.is_match(token) || GIT_HEX_REGEX.is_match(token) {
        return true;
    }
    if is_placeholder_value(token) {
        return true;
    }
    if token.starts_with('!')
        || token.contains("()")
        || (!was_quoted && token.contains('('))
        || token.contains("::")
        || token.contains("=>")
        || token.contains("->")
    {
        return true;
    }
    // URLs without embedded credentials
    if (token.starts_with("http://") || token.starts_with("https://")) && !token.contains('@') {
        return true;
    }
    // Relative/system file paths
    if token.starts_with("./") || token.starts_with("../") || token.starts_with('/') {
        return true;
    }
    // Dotted code property chains (e.g. req.body.plainToken, process.env.WEBHOOK_SECRET, auth_ctx.jwt_token)
    if !was_quoted && is_dotted_identifier_chain(token) {
        return true;
    }
    // Unquoted pure alphabetic/underscore identifiers (e.g. ProgressNotification, meeting_password)
    if !was_quoted && token.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
        return true;
    }
    // Snake_case or kebab-case identifier phrases without any digits
    if !token.chars().any(|c| c.is_ascii_digit())
        && (token.contains('_') || token.contains('-'))
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-')
    {
        return true;
    }

    false
}

/// Extracts a quoted or unquoted value starting at `val_start` in `input`.
/// Returns `(extracted_value, byte_start, byte_end, was_quoted)`.
fn extract_assigned_value(input: &str, val_start: usize) -> Option<(String, usize, usize, bool)> {
    let rest = &input[val_start..];
    let first = rest.chars().next()?;

    if first == '"' || first == '\'' {
        let quote = first;
        let inner_start = val_start + quote.len_utf8();
        let mut escaped = false;
        let mut end_rel = None;
        for (rel_idx, ch) in input[inner_start..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                end_rel = Some(rel_idx);
                break;
            }
            if ch == '\n' || ch == '\r' {
                break;
            }
        }
        let rel = end_rel?;
        let byte_end = inner_start + rel;
        let raw = &input[inner_start..byte_end];
        if raw.chars().count() < 12 {
            return None;
        }
        Some((raw.to_string(), inner_start, byte_end, true))
    } else {
        // Unquoted value: read until whitespace or statement delimiter
        let mut end_rel = rest.len();
        for (rel_idx, ch) in rest.char_indices() {
            if ch.is_whitespace()
                || matches!(ch, ',' | ';' | ')' | ']' | '}' | '[' | '"' | '\'' | '`')
            {
                end_rel = rel_idx;
                break;
            }
        }
        let raw = &rest[..end_rel];
        if raw.chars().count() < 12 {
            return None;
        }
        Some((raw.to_string(), val_start, val_start + end_rel, false))
    }
}

/// Detects high-entropy tokens inside sensitive assignment contexts with confidence metadata.
pub fn scan_contextual_entropy_detailed(input: &str) -> Vec<ContextualEntropyHit> {
    let mut detected = Vec::new();

    lazy_static::lazy_static! {
        static ref KEY_ASSIGN_REGEX: Regex = Regex::new(
            r#"(?i)(?:["']?)((?:[\p{L}\p{N}_]*(?:password|passwd|secret|secret_key|secretkey|private_key|privatekey|api_key|apikey|token|auth_token|client_secret|access_key)|(?:[\p{L}\p{N}_]*_)?pass)\b)(?:["']?)\s*[:=]\s*"#
        ).unwrap();
    }

    for cap in KEY_ASSIGN_REGEX.captures_iter(input) {
        let key_name = cap
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        if is_non_secret_key_name(&key_name) {
            continue;
        }

        let Some(full_match) = cap.get(0) else {
            continue;
        };
        let val_start = full_match.end();
        let Some((secret_str, start, end, was_quoted)) = extract_assigned_value(input, val_start)
        else {
            continue;
        };

        if is_known_false_positive(&secret_str, was_quoted) {
            continue;
        }

        let entropy = calculate_shannon_entropy(&secret_str);
        let has_digit = secret_str.chars().any(|c| c.is_ascii_digit());
        let has_upper = secret_str.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = secret_str.chars().any(|c| c.is_ascii_lowercase());
        let has_symbol = secret_str
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());
        let class_count = [has_digit, has_upper, has_lower, has_symbol]
            .into_iter()
            .filter(|&b| b)
            .count();

        // Note: log2(12) = 3.585, so 12-13 char high-complexity secrets cannot reach H >= 3.6
        let min_entropy = if secret_str.chars().count() <= 13 && class_count >= 3 {
            3.55
        } else {
            3.6
        };
        if entropy < min_entropy {
            continue;
        }

        // Quoted/unquoted multi-word natural language sentences (many spaces) are usually prose, not tokens
        let space_count = secret_str.chars().filter(|&c| c == ' ').count();
        if space_count >= 3 && !has_symbol && !has_digit {
            continue;
        }

        let confidence = if entropy >= 4.0 && secret_str.chars().count() >= 16 && class_count >= 3 {
            Confidence::High
        } else if class_count >= 2 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        detected.push(ContextualEntropyHit {
            value: secret_str,
            start,
            end,
            confidence,
            reason: format!(
                "High-entropy value (H={:.2}) assigned to sensitive key '{}'",
                entropy, key_name
            ),
        });
    }

    detected
}

/// Detects high-entropy tokens inside sensitive assignment contexts (e.g., password=..., token=...)
pub fn scan_contextual_entropy(input: &str) -> Vec<(String, usize, usize)> {
    scan_contextual_entropy_detailed(input)
        .into_iter()
        .map(|h| (h.value, h.start, h.end))
        .collect()
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

    #[test]
    fn test_false_positive_identifiers_and_placeholders() {
        let fp_cases = [
            ["plainToken: ", "req.body.plainToken,"].concat(),
            "nextPageToken = res.nextPageToken;".to_string(),
            "progressToken: ProgressNotification,".to_string(),
            ["const WEBHOOK_SECRET = ", "process.env.WEBHOOK_SECRET;"].concat(),
            ["auth_ctx.jwt_token = ", "jwtService.sign(payload);"].concat(),
            ["password: ", "meeting.password,"].concat(),
            r#"apiKey: "YOUR_API_KEY_HERE""#.to_string(),
            "token=${GITHUB_TOKEN_VALUE}".to_string(),
        ];
        for case in &fp_cases {
            assert!(
                scan_contextual_entropy(case).is_empty(),
                "Falsely flagged non-secret code/placeholder: {}",
                case
            );
        }
    }
}
