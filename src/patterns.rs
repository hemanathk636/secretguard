use regex::Regex;

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
    ]
}
