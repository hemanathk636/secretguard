use crate::SecretGuardEngine;
use regex::Regex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiiFinding {
    pub pii_type: String,
    pub original_snippet: String,
    pub sanitized_snippet: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PiiScanResult {
    pub has_pii: bool,
    pub sanitized_text: String,
    pub findings: Vec<PiiFinding>,
}

lazy_static::lazy_static! {
    // Visa, MasterCard, Amex, Discover Luhn-format credit card regex (no look-around)
    static ref RE_CREDIT_CARD: Regex = Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap();
    // US Social Security Number (SSN: \b\d{3}-\d{2}-\d{4}\b) without look-around
    static ref RE_SSN: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    // International Bank Account Number (IBAN)
    static ref RE_IBAN: Regex = Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap();
}

pub struct PiiScrubber;

impl PiiScrubber {
    /// Scrubs PII (Credit Cards, SSNs, IBANs) from user prompts or text files
    pub fn scrub_pii(text: &str, engine: &SecretGuardEngine) -> PiiScanResult {
        let mut sanitized = text.to_string();
        let mut findings = Vec::new();

        // 1. Credit Cards
        for cap in RE_CREDIT_CARD.find_iter(text) {
            let matched = cap.as_str();
            let masked = format!(
                "{}[REDACTED_CC]{}",
                &matched[..4],
                &matched[matched.len().saturating_sub(4)..]
            );
            findings.push(PiiFinding {
                pii_type: "Payment Card (PCI-DSS)".to_string(),
                original_snippet: matched.to_string(),
                sanitized_snippet: masked.clone(),
            });
            sanitized = sanitized.replace(matched, &masked);
        }

        // 2. SSN
        for cap in RE_SSN.find_iter(text) {
            let matched = cap.as_str();
            findings.push(PiiFinding {
                pii_type: "Social Security Number (PII)".to_string(),
                original_snippet: matched.to_string(),
                sanitized_snippet: "[REDACTED_SSN]".to_string(),
            });
            sanitized = sanitized.replace(matched, "[REDACTED_SSN]");
        }

        // 3. Run SecretGuard general secret scrubber as well
        let sec_res = engine.scan_and_sanitize(&sanitized);
        if sec_res.has_secret {
            sanitized = sec_res.sanitized_text;
        }

        let has_pii = !findings.is_empty() || sec_res.has_secret;

        PiiScanResult {
            has_pii,
            sanitized_text: sanitized,
            findings,
        }
    }

    /// CLI Handler for `secretguard scrub-pii`
    pub fn run_cli(args: &[String], engine: &SecretGuardEngine) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard scrub-pii - PII & Customer Data Redactor (PCI-DSS & GDPR)

USAGE:
    secretguard scrub-pii "<TEXT_OR_PROMPT>"
    secretguard scrub-pii --file <PATH>

Sanitizes Credit Cards, SSNs, and IBANs before sending prompts to LLMs or AI assistants.
"#
            );
            return;
        }

        let input_text = if args[0] == "--file" && args.len() >= 2 {
            std::fs::read_to_string(&args[1]).unwrap_or_default()
        } else {
            args.join(" ")
        };

        let result = Self::scrub_pii(&input_text, engine);
        if result.has_pii {
            eprintln!("🚨 PII or sensitive data detected and sanitized:");
            for f in &result.findings {
                eprintln!(
                    "  • \x1b[31m{}\x1b[0m: {} -> \x1b[32m{}\x1b[0m",
                    f.pii_type, f.original_snippet, f.sanitized_snippet
                );
            }
            eprintln!();
        }
        println!("{}", result.sanitized_text);
    }
}
