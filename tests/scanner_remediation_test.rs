mod common;

use secretguard::scanner::{execute_scan, parse_size_arg, ScanOptions};
use secretguard::verifier::KeyVerifier;
use secretguard::{Confidence, SecretGuardEngine};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sg_scanner_remediation_{}_{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_full_value_redaction_zero_partial_leakage() {
    let engine = SecretGuardEngine::new();

    let openai = common::synth_openai_key();
    let aws = format!("AKIA{}", "9X8Y7Z6W5V4U3T2S");
    let gh = common::synth_github_token();
    let pass = common::synth_entropy_pass();

    let cases = [
        (format!("OPENAI_API_KEY={}", openai), &openai[..4]),
        (format!(r#"{{"aws_key": "{}"}}"#, aws), &aws[..4]),
        (format!("token: '{}'", gh), &gh[..4]),
        (format!(r#"password = "{}""#, pass), &pass[..3]),
        (
            format!("password: \"{}\"", ["A9#kL", "\\\"m2$", "pQ8wZ10"].concat()),
            "A9#",
        ),
        (format!("ключ_password=\"{}\"", pass), &pass[..3]),
    ];

    for (line, leaked_prefix) in cases {
        let res = engine.scan_and_sanitize(&line);
        assert!(res.has_secret, "Expected detection for: {}", line);
        assert!(
            res.sanitized_text.contains("[REDACTED]"),
            "Expected [REDACTED] in: {}",
            res.sanitized_text
        );
        assert!(
            !res.sanitized_text.contains(leaked_prefix),
            "Partial secret prefix '{}' leaked in '{}'",
            leaked_prefix,
            res.sanitized_text
        );
    }

    // Verifier must also not leak prefix/suffix characters
    let v = KeyVerifier::verify_key(&openai);
    assert_eq!(v.masked_key, "[REDACTED]");
}

#[test]
fn test_contextual_false_positives_suppressed_and_true_positives_caught() {
    let engine = SecretGuardEngine::new();

    let false_positives = [
        ["password: ", "meeting.password,"].concat(),
        ["plainToken: ", "req.body.plainToken,"].concat(),
        "progressToken: ProgressNotification,".to_string(),
        "nextPageToken = res.nextPageToken;".to_string(),
        ["const WEBHOOK_SECRET = ", "process.env.WEBHOOK_SECRET;"].concat(),
        ["auth_ctx.jwt_token = ", "jwtService.sign(payload);"].concat(),
        r#"apiKey: "YOUR_API_KEY_HERE""#.to_string(),
        "secret: ${APP_CLIENT_SECRET}".to_string(),
        "token: <insert-token-here>".to_string(),
        "password: xxxxxxxxxxxxxxxx".to_string(),
    ];

    for fp in &false_positives {
        let res = engine.scan_and_sanitize(fp);
        assert!(
            !res.has_secret,
            "False positive on '{}': rules={:?}, sanitized='{}'",
            fp, res.matched_rules, res.sanitized_text
        );
    }

    // Genuine credentials in Markdown and minified JS must still be detected
    let md_line = format!("Example leak in docs: `AKIA{}`", "1234567890ABCDEF");
    let md_res = engine.scan_and_sanitize(&md_line);
    assert!(md_res.has_secret);
    assert_eq!(md_res.findings[0].confidence, Confidence::High);
    assert_eq!(md_res.findings[0].rule_id, "SG001");

    // PKCS#8 header (no RSA/EC prefix)
    let pkcs8 = common::synth_pkcs8_header();
    assert!(engine.scan_and_sanitize(&pkcs8).has_secret);
}

#[test]
fn test_scanner_grouping_minified_large_binary_and_utf16() {
    let dir = temp_dir("suite");

    // 1. Multiple occurrences in same file grouped, distinct secrets on same line preserved
    let k1 = format!("AKIA{}", "1111222233334444");
    let k2 = format!("AKIA{}", "5555666677778888");
    fs::write(
        dir.join("keys.env"),
        format!("K1={} K2={}\nK3={}\n", k1, k2, k1),
    )
    .unwrap();

    // 2. Minified JS file with huge line + genuine secret
    let filler = "var a=1;".repeat(600);
    let min_secret = format!("sk-proj-{}", "ZyXwVuTsRqPoNmLkJiHgFeDcBa98765432");
    fs::write(
        dir.join("app.min.js"),
        format!("{};const k='{}';{}\n", filler, min_secret, filler),
    )
    .unwrap();

    // 3. Binary file with NUL bytes
    fs::write(
        dir.join("blob.dat"),
        b"\x00\x01\x02AKIA1111222233334444\x00",
    )
    .unwrap();

    // 4. Large file above custom threshold
    fs::write(dir.join("huge.txt"), "a".repeat(12 * 1024)).unwrap();

    // 5. UTF-16 LE BOM file with secret
    let utf16_str = format!(
        "SECRET_KEY=ghp_{}\n",
        "abcdef1234567890abcdef1234567890abcd"
    );
    let mut utf16_bytes = vec![0xFFu8, 0xFEu8];
    for u in utf16_str.encode_utf16() {
        utf16_bytes.extend_from_slice(&u.to_le_bytes());
    }
    fs::write(dir.join("win.env"), utf16_bytes).unwrap();

    let engine = SecretGuardEngine::new();
    let opts = ScanOptions {
        target: dir.clone(),
        max_file_size: parse_size_arg("10KB").unwrap(),
        verbose: true,
        ..Default::default()
    };

    let report = execute_scan(&engine, &opts).unwrap();
    assert!(!report.clean);
    assert_eq!(report.stats.binary_files_skipped, 1);
    assert_eq!(report.stats.large_files_skipped, 1);
    // keys.env has 3 unique AWS key occurrences across 2 lines -> 1 group with occurrences == 3
    let keys_group = report
        .groups
        .iter()
        .find(|g| g.file.ends_with("keys.env") && g.rule_id == "SG001")
        .expect("keys.env SG001 group");
    assert_eq!(keys_group.occurrences, 3);
    assert_eq!(keys_group.lines, vec![1, 2]);
    // Minified snippet is bounded and does not leak secret
    let min_group = report
        .groups
        .iter()
        .find(|g| g.file.ends_with("app.min.js"))
        .expect("app.min.js group");
    assert!(min_group.sample_redacted.len() <= 160);
    assert!(!min_group.sample_redacted.contains("ZyXw"));
    // UTF-16 file detected
    assert!(report.groups.iter().any(|g| g.file.ends_with("win.env")));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_scanner_exclude_and_include_controls() {
    let dir = temp_dir("controls");
    fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
    fs::write(
        dir.join("node_modules/pkg/leak.js"),
        format!("const a = 'AKIA{}';\n", "AAAABBBBCCCCDDDD"),
    )
    .unwrap();
    fs::write(
        dir.join("ignored.log"),
        format!("AKIA{}\n", "EEEEFFFF11112222"),
    )
    .unwrap();

    let engine = SecretGuardEngine::new();
    let opts = ScanOptions {
        target: dir.clone(),
        excludes: vec!["*.log".to_string()],
        includes: vec!["node_modules".to_string()],
        ..Default::default()
    };
    let report = execute_scan(&engine, &opts).unwrap();
    assert!(report
        .groups
        .iter()
        .any(|g| g.file.contains("node_modules")));
    assert!(!report
        .groups
        .iter()
        .any(|g| g.file.ends_with("ignored.log")));
    assert_eq!(report.stats.files_ignored, 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_adversarial_edge_cases_and_encodings() {
    let engine = SecretGuardEngine::new();

    // 1. Bracket property access must not false-positive
    for fp in [
        "const t = window.localStorage['AUTH_TOKEN'];",
        "const w = process.env['WEBHOOK_SECRET'];",
    ] {
        let res = engine.scan_and_sanitize(fp);
        assert!(!res.has_secret, "False positive on '{}'", fp);
    }

    // 2. secret_key / private_key assignment must be detected and fully redacted
    let sk = format!(r#"secret_key = "{}""#, "X9#kLm!2$pQ8wZ10_live");
    let sk_res = engine.scan_and_sanitize(&sk);
    assert!(sk_res.has_secret);
    assert!(!sk_res.sanitized_text.contains("X9#"));
    assert!(sk_res.sanitized_text.contains("[REDACTED]"));

    // 3. DB URI containing '@' inside password must not leak suffix after first '@'
    let db_pass_at = common::synth_db_pass_with_at();
    let db_uri = format!("DATABASE_URL={}", common::synth_db_uri(&db_pass_at));
    let db_res = engine.scan_and_sanitize(&db_uri);
    assert!(db_res.has_secret);
    assert!(!db_res.sanitized_text.contains("ssword123!"));
    assert!(!db_res.sanitized_text.contains("admin"));

    // 4. Multiple distinct secrets on a single line must all be redacted
    let multi = format!(
        "AWS=AKIA{} OPENAI={} PASS={}",
        "1234567890ABCDEF",
        common::synth_openai_key(),
        common::synth_entropy_pass()
    );
    let multi_res = engine.scan_and_sanitize(&multi);
    assert!(multi_res.has_secret);
    assert!(!multi_res.sanitized_text.contains("AKIA"));
    assert!(!multi_res.sanitized_text.contains("sk-proj"));
    assert!(!multi_res.sanitized_text.contains("X9#"));

    // 5. Single-file large-file cap + UTF-16 BE + UTF-8 BOM + hidden file
    let dir = temp_dir("adversarial");
    let big_file = dir.join("single_big.txt");
    fs::write(&big_file, "x".repeat(4096)).unwrap();
    let single_report = execute_scan(
        &engine,
        &ScanOptions {
            target: big_file,
            max_file_size: 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(single_report.stats.large_files_skipped, 1);
    assert_eq!(single_report.stats.files_scanned, 0);

    // UTF-16 BE BOM + hidden file
    let be_str = format!("TOKEN=ghp_{}\n", "1234567890abcdef1234567890abcdef1234");
    let mut be_bytes = vec![0xFEu8, 0xFFu8];
    for u in be_str.encode_utf16() {
        be_bytes.extend_from_slice(&u.to_be_bytes());
    }
    fs::write(dir.join(".hidden_be.env"), be_bytes).unwrap();

    // UTF-8 BOM
    let mut u8_bom = vec![0xEFu8, 0xBBu8, 0xBFu8];
    u8_bom.extend_from_slice(format!("AWS=AKIA{}\n", "9999888877776666").as_bytes());
    fs::write(dir.join(".utf8_bom.env"), u8_bom).unwrap();

    let dir_report = execute_scan(
        &engine,
        &ScanOptions {
            target: dir.clone(),
            max_file_size: 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(dir_report.stats.large_files_skipped, 1);
    assert!(dir_report
        .groups
        .iter()
        .any(|g| g.file.ends_with(".hidden_be.env")));
    assert!(dir_report
        .groups
        .iter()
        .any(|g| g.file.ends_with(".utf8_bom.env")));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_nul_byte_and_bomless_utf16_adversarial_bypass_remediation() {
    let engine = SecretGuardEngine::new();
    let dir = temp_dir("nul_bypass_remediation");
    let openai = common::synth_openai_key();

    // 1 & 2. NUL byte before synthetic secret within first 4096 bytes
    let mut nul_prefix = vec![0x00u8];
    nul_prefix.extend_from_slice(format!("OPENAI_API_KEY={}\n", openai).as_bytes());
    fs::write(dir.join("nul_prefix.env"), &nul_prefix).unwrap();

    // 3. Secret placed after >4096 NUL bytes (NUL-padding bypass attempt)
    let mut nul_padded = vec![0x00u8; 5000];
    nul_padded.extend_from_slice(format!("\nOPENAI_API_KEY={}\n", openai).as_bytes());
    fs::write(dir.join("nul_padded.env"), &nul_padded).unwrap();

    // 3b. NUL bytes embedded inside/between characters of the secret value
    let split_mid = openai.len() / 2;
    let mut nul_inside = Vec::new();
    nul_inside.extend_from_slice(b"OPENAI_API_KEY=");
    nul_inside.extend_from_slice(&openai.as_bytes()[..4]);
    nul_inside.push(0x00);
    nul_inside.extend_from_slice(&openai.as_bytes()[4..split_mid]);
    nul_inside.push(0x00);
    nul_inside.extend_from_slice(&openai.as_bytes()[split_mid..]);
    nul_inside.push(b'\n');
    fs::write(dir.join("nul_inside.env"), &nul_inside).unwrap();

    // 4. BOM-less UTF-16LE containing synthetic secret
    let le_str = format!("OPENAI_API_KEY={}\n", openai);
    let mut bomless_le = Vec::new();
    for u in le_str.encode_utf16() {
        bomless_le.extend_from_slice(&u.to_le_bytes());
    }
    fs::write(dir.join("bomless_le.env"), &bomless_le).unwrap();

    // 5. BOM-less UTF-16BE containing synthetic secret
    let mut bomless_be = Vec::new();
    for u in le_str.encode_utf16() {
        bomless_be.extend_from_slice(&u.to_be_bytes());
    }
    fs::write(dir.join("bomless_be.env"), &bomless_be).unwrap();

    // 6. UTF-16LE BOM
    let mut bom_le = vec![0xFFu8, 0xFEu8];
    bom_le.extend_from_slice(&bomless_le);
    fs::write(dir.join("bom_le.env"), &bom_le).unwrap();

    // 7. Genuine binary blob (random-like control bytes + invalid UTF-8) must remain skipped
    let mut genuine_bin = Vec::with_capacity(8192);
    for i in 0..8192usize {
        genuine_bin.push(((i * 37 + 13) % 256) as u8);
    }
    fs::write(dir.join("blob.dat"), &genuine_bin).unwrap();

    // Verify decode_buffer_text does not allocate a String for genuine binary data
    let (is_bin, bin_text) = secretguard::scanner::decode_buffer_text(&genuine_bin);
    assert!(is_bin);
    assert!(bin_text.is_empty());

    let report = execute_scan(
        &engine,
        &ScanOptions {
            target: dir.clone(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(report.stats.binary_files_skipped, 1);
    for expected in [
        "nul_prefix.env",
        "nul_padded.env",
        "nul_inside.env",
        "bomless_le.env",
        "bomless_be.env",
        "bom_le.env",
    ] {
        assert!(
            report.groups.iter().any(|g| g.file.ends_with(expected)),
            "Expected secret finding in '{}' after NUL/UTF-16 remediation",
            expected
        );
    }

    let _ = fs::remove_dir_all(&dir);
}
