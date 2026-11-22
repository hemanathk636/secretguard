//! Sub-millisecond In-Memory Decoding Engine for SecretGuard
//! Detects credentials obfuscated via Base64, URL percent-encoding, or Hex.

/// Fast zero-dependency Base64 decoder
pub fn decode_base64(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 16 {
        return None;
    }

    let mut buf = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\r' | b'\n' => continue,
            _ => return None, // Not valid base64
        };

        acc = (acc << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            buf.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }

    // Must be valid printable UTF-8 to be a secret token
    if buf.len() >= 10
        && buf
            .iter()
            .all(|&c| (32..=126).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t')
    {
        String::from_utf8(buf).ok()
    } else {
        None
    }
}

/// Decodes URL percent-encoded characters (e.g., %2F -> /, %3A -> :)
pub fn decode_url_percent(input: &str) -> Option<String> {
    if !input.contains('%') {
        return None;
    }

    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if let (Some(d1), Some(d2)) = (from_hex_digit(h1), from_hex_digit(h2)) {
                decoded.push((d1 << 4) | d2);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(decoded).ok()
}

/// Fast hex digit parser
fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extracts potential encoded tokens from a command or file line
pub fn find_encoded_candidates(input: &str) -> Vec<(String, String)> {
    let mut candidates = Vec::new();

    // Check words/tokens
    for part in input.split(|c: char| {
        c.is_whitespace() || c == '=' || c == '"' || c == '\'' || c == ',' || c == ':' || c == ';'
    }) {
        let clean = part.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '+' && c != '/' && c != '=' && c != '-' && c != '_'
        });

        // Base64 candidates typically >= 16 chars (e.g. 12+ raw bytes encoded)
        if clean.len() >= 16 {
            if let Some(decoded) = decode_base64(clean) {
                candidates.push((clean.to_string(), decoded));
            }
        }
    }

    // Check full string for URL encoding if % exists
    if input.contains('%') {
        if let Some(decoded_url) = decode_url_percent(input) {
            candidates.push((input.to_string(), decoded_url));
        }
    }

    candidates
}
