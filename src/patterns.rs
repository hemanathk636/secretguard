use regex::Regex;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone)]
pub struct SecretPattern {
    pub rule_id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub regex: Regex,
}

pub fn get_high_confidence_patterns() -> Vec<SecretPattern> {
    vec![
        // AWS Access Key ID
        SecretPattern {
            rule_id: "SG001",
            name: "AWS Access Key",
            description: "Amazon Web Services Access Key ID",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        },
        // OpenAI API Key (Legacy & Project format)
        SecretPattern {
            rule_id: "SG002",
            name: "OpenAI API Key",
            description: "OpenAI Platform/Project Secret Token",
            severity: Severity::Critical,
            regex: Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b").unwrap(),
        },
        // Anthropic Claude API Key
        SecretPattern {
            rule_id: "SG003",
            name: "Anthropic API Key",
            description: "Anthropic Claude API Secret Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b").unwrap(),
        },
        // GitHub Personal Access Token (Classic & Fine-Grained)
        SecretPattern {
            rule_id: "SG004",
            name: "GitHub Token",
            description: "GitHub Personal Access or OAuth Token",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b").unwrap(),
        },
        // Slack Tokens (Bot, User, Workspace)
        SecretPattern {
            rule_id: "SG005",
            name: "Slack Token",
            description: "Slack Bot/User Authentication Token",
            severity: Severity::High,
            regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z_-]{10,}\b").unwrap(),
        },
        // Slack Incoming Webhook
        SecretPattern {
            rule_id: "SG006",
            name: "Slack Webhook",
            description: "Slack Incoming Webhook URL",
            severity: Severity::High,
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}").unwrap(),
        },
        // Stripe API Keys (Live & Test Secret Keys)
        SecretPattern {
            rule_id: "SG007",
            name: "Stripe Secret Key",
            description: "Stripe Payment Gateway Secret API Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b").unwrap(),
        },
        // Google Cloud / Gemini API Key
        SecretPattern {
            rule_id: "SG008",
            name: "Google API Key",
            description: "Google Cloud / Gemini API Key",
            severity: Severity::High,
            regex: Regex::new(r"\bAIza[0-9A-Za-z-_]{35}\b").unwrap(),
        },
        // Hugging Face Access Token
        SecretPattern {
            rule_id: "SG009",
            name: "HuggingFace Token",
            description: "Hugging Face User Access Token",
            severity: Severity::High,
            regex: Regex::new(r"\bhf_[a-zA-Z0-9]{34,}\b").unwrap(),
        },
        // Supabase / JWT service role tokens
        SecretPattern {
            rule_id: "SG010",
            name: "JWT / Supabase Token",
            description: "JSON Web Token / Supabase Service Role Key",
            severity: Severity::High,
            regex: Regex::new(r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        // Private Key Blocks
        SecretPattern {
            rule_id: "SG011",
            name: "Private Key Block",
            description: "PEM/OpenSSH/RSA/PGP Private Key Header",
            severity: Severity::Critical,
            regex: Regex::new(r"-----BEGIN (?:(?:RSA|OPENSSH|EC|DSA|PGP|ENCRYPTED) )?PRIVATE KEY-----").unwrap(),
        },
        // Database Connection Strings with Passwords
        SecretPattern {
            rule_id: "SG012",
            name: "Database Connection URI",
            description: "Database Connection String containing plaintext password",
            severity: Severity::Critical,
            regex: Regex::new(r"(?i)\b(postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqps?):\/\/[a-zA-Z0-9_.-]+:\S{3,}@[a-zA-Z0-9_.-]+").unwrap(),
        },
        // SendGrid API Key
        SecretPattern {
            rule_id: "SG013",
            name: "SendGrid API Key",
            description: "SendGrid Email API Token",
            severity: Severity::High,
            regex: Regex::new(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b").unwrap(),
        },
        // Postman API Key
        SecretPattern {
            rule_id: "SG014",
            name: "Postman API Key",
            description: "Postman Workspace API Token",
            severity: Severity::High,
            regex: Regex::new(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b").unwrap(),
        },
        // NPM Access Token
        SecretPattern {
            rule_id: "SG015",
            name: "NPM Access Token",
            description: "Node Package Manager Automation/Publishing Token",
            severity: Severity::Critical,
            regex: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(),
        },
        // Twilio API Key
        SecretPattern {
            rule_id: "SG016",
            name: "Twilio API Key",
            description: "Twilio Telephony & SMS API Key",
            severity: Severity::High,
            regex: Regex::new(r"\bSK[0-9a-fA-F]{32}\b").unwrap(),
        },
        // Resend API Key
        SecretPattern {
            rule_id: "SG017",
            name: "Resend API Key",
            description: "Resend Email Service API Token",
            severity: Severity::High,
            regex: Regex::new(r"\bre_[a-zA-Z0-9]{32,}\b").unwrap(),
        },
        // Sentry Auth Token
        SecretPattern {
            rule_id: "SG018",
            name: "Sentry Auth Token",
            description: "Sentry Error Monitoring Authentication Token",
            severity: Severity::High,
            regex: Regex::new(r"\bsntrys_[a-zA-Z0-9]{64}\b").unwrap(),
        },
        // Shopify Access Token
        SecretPattern {
            rule_id: "SG019",
            name: "Shopify Token",
            description: "Shopify Admin/Storefront Access Token",
            severity: Severity::High,
            regex: Regex::new(r"\bshpat_[a-fA-F0-9]{32}\b").unwrap(),
        },
        // Square Access Token
        SecretPattern {
            rule_id: "SG020",
            name: "Square Access Token",
            description: "Square Payments Merchant Access Token",
            severity: Severity::High,
            regex: Regex::new(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b").unwrap(),
        },
        // PyPI API Token
        SecretPattern {
            rule_id: "SG021",
            name: "PyPI Token",
            description: "Python Package Index Upload API Token",
            severity: Severity::Critical,
            regex: Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b").unwrap(),
        },
        // Discord Bot Token
        SecretPattern {
            rule_id: "SG022",
            name: "Discord Bot Token",
            description: "Discord Application Bot Token",
            severity: Severity::High,
            regex: Regex::new(r"\b[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,38}\b").unwrap(),
        },
        // Grafana Service Account Token
        SecretPattern {
            rule_id: "SG023",
            name: "Grafana Token",
            description: "Grafana Cloud / Service Account Token",
            severity: Severity::High,
            regex: Regex::new(r"\bglsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}\b").unwrap(),
        },
        // Linear API Key
        SecretPattern {
            rule_id: "SG024",
            name: "Linear API Key",
            description: "Linear Project Management Personal API Key",
            severity: Severity::High,
            regex: Regex::new(r"\blin_api_[a-zA-Z0-9]{40}\b").unwrap(),
        },
    ]
}
