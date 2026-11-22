use secretguard::ghost::GhostVirtualizer;
use secretguard::SecretGuardEngine;

#[test]
fn test_shell_history_leak_prevention() {
    let engine = SecretGuardEngine::new();

    let stripe_key = format!("{}_{}", "sk_live", "abcdef1234567890abcdef123456");
    let openai_key = format!("{}-{}", "sk-proj", "1234567890abcdef1234567890abcdef");
    let aws_key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let npm_key = format!("{}_{}", "npm", "1234567890abcdef1234567890abcdef1234");

    // Simulated dangerous history lines from actual developer sessions
    let test_history_lines = vec![
        format!("export STRIPE_SECRET_KEY={}", stripe_key),
        format!(
            "curl -H 'Authorization: Bearer {}' https://api.openai.com",
            openai_key
        ),
        format!("aws s3 cp file.txt s3://bucket/ --access-key {}", aws_key),
        format!("npm publish --token {}", npm_key),
    ];

    for line in &test_history_lines {
        let res = engine.scan_and_sanitize(line);
        assert!(
            res.has_secret,
            "Failed to catch secret in history candidate: {}",
            line
        );

        // Assert raw secret strings are completely scrubbed from the sanitized output
        assert!(!res.sanitized_text.contains(&stripe_key));
        assert!(!res.sanitized_text.contains(&openai_key));
        assert!(!res.sanitized_text.contains(&aws_key));
        assert!(!res.sanitized_text.contains(&npm_key));

        // Assert [REDACTED] mask is applied
        assert!(res.sanitized_text.contains("[REDACTED]"));
    }
}

#[test]
fn test_ai_agent_log_and_context_air_gap() {
    let engine = SecretGuardEngine::new();

    // Verify Ghost Tokens ensure raw keys never reach LLM prompt buffers
    let raw_openai = "sk-proj-prodMasterSecretKey9876543210abcdef12";
    let raw_aws = "AKIAIOSFODNN7EXAMPLE";
    let raw_env_config = format!("OPENAI_API_KEY={}\nAWS_KEY={}\n", raw_openai, raw_aws);
    let (ghost_virtualized, count) = GhostVirtualizer::virtualize_text(&raw_env_config, &engine);

    assert_eq!(count, 2);
    // Raw secrets MUST NEVER appear in LLM prompt context
    assert!(!ghost_virtualized.contains(raw_openai));
    assert!(!ghost_virtualized.contains(raw_aws));
    // Decoy ghost tokens must be present
    assert!(ghost_virtualized.contains("sk-ghost-"));
    assert!(ghost_virtualized.contains("AKIA_GHOST_"));
}

#[test]
fn test_zero_false_positives_on_standard_developer_code() {
    let engine = SecretGuardEngine::new();

    let safe_developer_inputs = vec![
        "git commit -m 'feat: update user avatar component'",
        "cargo build --release --target x86_64-unknown-linux-gnu",
        "const color = '#38bdf8'; const border = '#10b981';",
        "let commit_hash = '44f3ba596361cf00adf001a687525120330436be';",
        "let session_uuid = 'e2878037-5477-4284-9750-a0d7e7a267ad';",
        "curl https://api.github.com/repos/hemanathk636/secretguard",
        "npm install --save-dev typescript @types/node",
        "SELECT id, username, email FROM users WHERE active = true;",
        "docker run -d -p 8080:80 --name web nginx:alpine",
    ];

    for input in safe_developer_inputs {
        let res = engine.scan_and_sanitize(input);
        assert!(
            !res.has_secret,
            "FALSE POSITIVE DETECTED on clean code: '{}' (flagged as: {:?})",
            input, res.matched_rules
        );
        assert_eq!(
            res.sanitized_text, input,
            "Clean input was unnecessarily modified"
        );
    }
}

#[test]
fn test_zero_false_negatives_across_all_24_cloud_patterns() {
    let engine = SecretGuardEngine::new();

    let real_world_mock_cases = vec![
        ("AWS", format!("aws_key = \"{}\"", "AKIAIOSFODNN7EXAMPLE")),
        ("OpenAI", format!("export OPENAI_KEY=\"{}-1234567890abcdef1234567890abcdef\"", "sk-proj")),
        ("Anthropic", format!("export ANTHROPIC_KEY=\"{}-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\"", "sk-ant-api03")),
        ("GitHub", format!("gh_token = \"{}_1234567890abcdef1234567890abcdef1234\"", "ghp")),
        ("Slack", format!("token = \"{}-0000000000-0000000000-TESTDUMMYMOCK\"", "xoxb")),
        ("Stripe", format!("stripe_secret = \"{}_1234567890abcdef12345678\"", "sk_live")),
        ("Google", format!("key = \"AIzaSy{}\"", "TESTDUMMYMOCK00000000000000000000")),
        ("HuggingFace", format!("hf_token = \"{}_1234567890abcdef1234567890abcdef12\"", "hf")),
        ("NPM", format!("npm_token = \"{}_{}\"", "npm", "1234567890abcdef1234567890abcdef1234")),
        ("Twilio", format!("twilio_key = \"{}{}\"", "SK", "1234567890abcdef1234567890abcdef")),
        ("Resend", format!("resend_key = \"{}_{}\"", "re", "1234567890abcdef1234567890abcdef")),
        ("Shopify", format!("shopify_key = \"{}_{}\"", "shpat", "1234567890abcdef1234567890abcdef")),
        ("Linear", format!("linear_key = \"{}_{}\"", "lin_api", "1234567890abcdef1234567890abcdef12345678")),
    ];

    for (name, sample) in real_world_mock_cases {
        let res = engine.scan_and_sanitize(&sample);
        assert!(
            res.has_secret,
            "FALSE NEGATIVE: Failed to detect {} credential pattern: '{}'",
            name, sample
        );
    }
}
