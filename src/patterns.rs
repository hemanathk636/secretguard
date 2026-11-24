use regex::Regex;

#[derive(Clone)]
pub struct SecretPattern {
    pub name: &'static str,
    pub description: &'static str,
    pub regex: Regex,
}

pub fn get_high_confidence_patterns() -> Vec<SecretPattern> {
    vec![
        // AWS Access Key ID
        SecretPattern {
            name: "AWS Access Key",
            description: "Amazon Web Services Access Key ID",
            regex: Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        },
        // OpenAI API Key (Legacy & Project format)
        SecretPattern {
            name: "OpenAI API Key",
            description: "OpenAI Platform/Project Secret Token",
            regex: Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b").unwrap(),
        },
        // Anthropic Claude API Key
        SecretPattern {
            name: "Anthropic API Key",
            description: "Anthropic Claude API Secret Key",
            regex: Regex::new(r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}\b").unwrap(),
        },
        // GitHub Personal Access Token (Classic & Fine-Grained)
        SecretPattern {
            name: "GitHub Token",
            description: "GitHub Personal Access or OAuth Token",
            regex: Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b").unwrap(),
        },
        // Slack Tokens (Bot, User, Workspace)
        SecretPattern {
            name: "Slack Token",
            description: "Slack Bot/User Authentication Token",
            regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z_-]{10,}\b").unwrap(),
        },
        // Slack Incoming Webhook
        SecretPattern {
            name: "Slack Webhook",
            description: "Slack Incoming Webhook URL",
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}").unwrap(),
        },
        // Stripe API Keys (Live & Test Secret Keys)
        SecretPattern {
            name: "Stripe Secret Key",
            description: "Stripe Payment Gateway Secret API Key",
            regex: Regex::new(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b").unwrap(),
        },
        // Google Cloud / Gemini API Key
        SecretPattern {
            name: "Google API Key",
            description: "Google Cloud / Gemini API Key",
            regex: Regex::new(r"\bAIza[0-9A-Za-z-_]{35}\b").unwrap(),
        },
        // Hugging Face Access Token
        SecretPattern {
            name: "HuggingFace Token",
            description: "Hugging Face User Access Token",
            regex: Regex::new(r"\bhf_[a-zA-Z0-9]{34,}\b").unwrap(),
        },
        // Supabase / JWT service role tokens
        SecretPattern {
            name: "JWT / Supabase Token",
            description: "JSON Web Token / Supabase Service Role Key",
            regex: Regex::new(r"\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        // Private Key Blocks
        SecretPattern {
            name: "Private Key Block",
            description: "PEM/OpenSSH/RSA/PGP Private Key Header",
            regex: Regex::new(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)? PRIVATE KEY-----").unwrap(),
        },
        // Database Connection Strings with Passwords
        SecretPattern {
            name: "Database Connection URI",
            description: "Database Connection String containing plaintext password",
            regex: Regex::new(r"(?i)\b(postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s]{3,}@[a-zA-Z0-9_.-]+").unwrap(),
        },
        // SendGrid API Key
        SecretPattern {
            name: "SendGrid API Key",
            description: "SendGrid Email API Token",
            regex: Regex::new(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b").unwrap(),
        },
        // Postman API Key
        SecretPattern {
            name: "Postman API Key",
            description: "Postman Workspace API Token",
            regex: Regex::new(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b").unwrap(),
        },
        // NPM Access Token
        SecretPattern {
            name: "NPM Access Token",
            description: "Node Package Manager Automation/Publishing Token",
            regex: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(),
        },
        // Twilio API Key
        SecretPattern {
            name: "Twilio API Key",
            description: "Twilio Telephony & SMS API Key",
            regex: Regex::new(r"\bSK[0-9a-fA-F]{32}\b").unwrap(),
        },
        // Resend API Key
        SecretPattern {
            name: "Resend API Key",
            description: "Resend Email Service API Token",
            regex: Regex::new(r"\bre_[a-zA-Z0-9]{32,}\b").unwrap(),
        },
        // Sentry Auth Token
        SecretPattern {
            name: "Sentry Auth Token",
            description: "Sentry Error Monitoring Authentication Token",
            regex: Regex::new(r"\bsntrys_[a-zA-Z0-9]{64}\b").unwrap(),
        },
        // Shopify Access Token
        SecretPattern {
            name: "Shopify Token",
            description: "Shopify Admin/Storefront Access Token",
            regex: Regex::new(r"\bshpat_[a-fA-F0-9]{32}\b").unwrap(),
        },
        // Square Access Token
        SecretPattern {
            name: "Square Access Token",
            description: "Square Payments Merchant Access Token",
            regex: Regex::new(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b").unwrap(),
        },
        // PyPI API Token
        SecretPattern {
            name: "PyPI Token",
            description: "Python Package Index Upload API Token",
            regex: Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b").unwrap(),
        },
        // Discord Bot Token
        SecretPattern {
            name: "Discord Bot Token",
            description: "Discord Application Bot Token",
            regex: Regex::new(r"\b[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9-_]{6}\.[A-Za-z0-9-_]{27,38}\b").unwrap(),
        },
        // Grafana Service Account Token
        SecretPattern {
            name: "Grafana Token",
            description: "Grafana Cloud / Service Account Token",
            regex: Regex::new(r"\bglsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}\b").unwrap(),
        },
        // Linear API Key
        SecretPattern {
            name: "Linear API Key",
            description: "Linear Project Management Personal API Key",
            regex: Regex::new(r"\blin_api_[a-zA-Z0-9]{40}\b").unwrap(),
        },
    ]
}
