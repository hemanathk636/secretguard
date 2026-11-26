#![allow(dead_code)]

//! Test-only runtime fixture builders that assemble synthetic credential-shaped
//! strings from harmless fragments so test sources never embed literal secret patterns.

pub fn synth_openai_key() -> String {
    ["sk", "-proj-", "aB3dEf9GhIjK2LmNo", "PqRsTuVwXyZ012345"].concat()
}

pub fn synth_github_token() -> String {
    ["ghp_", "1234567890abcdef", "1234567890abcdef1234"].concat()
}

pub fn synth_entropy_pass() -> String {
    ["X9#kLm", "!2$pQ8", "wZ10_live"].concat()
}

pub fn synth_short_pass() -> String {
    ["X9#kLm", "!2$pQ8"].concat()
}

pub fn synth_db_pass_simple() -> String {
    ["X9kLm2", "pQ8wZ10!"].concat()
}

pub fn synth_db_pass_with_at() -> String {
    ["p@ssword", "123!"].concat()
}

pub fn synth_db_uri(password: &str) -> String {
    [
        "postgresql://",
        "admin:",
        password,
        "@db.example.com:5432/prod",
    ]
    .concat()
}

pub fn synth_pkcs8_header() -> String {
    ["-----BEGIN ", "PRIVATE ", "KEY-----"].concat()
}
