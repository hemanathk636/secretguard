use regex::Regex;

/// Generates a format-preserving synthetic mock token that matches the exact length,
/// prefix, and structure of real API tokens. This allows AI coding agents (Claude Code, Cursor)
/// and test suites to execute without failing regex or format validation.
pub fn generate_synthetic_token(rule_name: &str, matched_str: &str) -> String {
    let len = matched_str.len();

    match rule_name {
        "AWS Access Key" => {
            let prefix = if matched_str.len() >= 4 {
                &matched_str[..4]
            } else {
                "AKIA"
            };
            format!("{}FAKE000000000000", prefix)
        }
        "OpenAI API Key" => {
            if matched_str.starts_with("sk-proj-") {
                let prefix = "sk-proj-";
                let target_len = len.saturating_sub(prefix.len());
                let filler = "TESTDUMMYMOCK00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                let suffix = if target_len <= filler.len() {
                    &filler[..target_len]
                } else {
                    filler
                };
                format!("{}{}", prefix, suffix)
            } else {
                let prefix = "sk-";
                let target_len = len.saturating_sub(prefix.len());
                let filler = "TESTDUMMYMOCK00000000000000000000000000000000000000000000000000000000000000000000000000000000";
                let suffix = if target_len <= filler.len() {
                    &filler[..target_len]
                } else {
                    filler
                };
                format!("{}{}", prefix, suffix)
            }
        }
        "Anthropic API Key" => {
            let prefix = "sk-ant-api03-";
            let target_len = len.saturating_sub(prefix.len());
            let filler = "TESTDUMMYMOCK00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "GitHub Token" => {
            let prefix = if matched_str.len() >= 4 && matched_str.chars().nth(3) == Some('_') {
                &matched_str[..4]
            } else {
                "ghp_"
            };
            let target_len = len.saturating_sub(prefix.len());
            let filler = "TESTDUMMYMOCK000000000000000000000000000000000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "Slack Token" => {
            let prefix = if matched_str.len() >= 5 {
                &matched_str[..5]
            } else {
                "xoxb-"
            };
            let target_len = len.saturating_sub(prefix.len());
            let filler = "0000000000-0000000000000-TESTDUMMYMOCK00000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "Stripe Secret Key" => {
            let prefix = if matched_str.starts_with("sk_live_") {
                "sk_test_"
            } else if matched_str.starts_with("rk_live_") {
                "rk_test_"
            } else if matched_str.len() >= 8 {
                &matched_str[..8]
            } else {
                "sk_test_"
            };
            let target_len = len.saturating_sub(prefix.len());
            let filler = "TESTDUMMYMOCK0000000000000000000000000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "Google API Key" => {
            let prefix = "AIzaSy";
            let target_len = len.saturating_sub(prefix.len());
            let filler = "TESTDUMMYMOCK0000000000000000000000000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "HuggingFace Token" => {
            let prefix = "hf_";
            let target_len = len.saturating_sub(prefix.len());
            let filler = "TESTDUMMYMOCK0000000000000000000000000000000000000000";
            let suffix = if target_len <= filler.len() {
                &filler[..target_len]
            } else {
                filler
            };
            format!("{}{}", prefix, suffix)
        }
        "Database Connection URI" => {
            let re = Regex::new(r"(:)[^@\s]{3,}(@)").unwrap();
            re.replace(matched_str, "${1}SYNTHETIC_MOCK_PASSWORD${2}")
                .to_string()
        }
        _ => {
            let filler = "MOCK_KEY_FAKE_CREDENTIAL_00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            if len <= filler.len() {
                filler[..len].to_string()
            } else {
                format!("[SYNTHETIC_MOCK_{}]", len)
            }
        }
    }
}
