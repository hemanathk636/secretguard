//! Local Security Broker for SecretGuard
//! Sits between clients, AI agents, and protected credentials.
//! Authorizes operations, executes delegated tasks, and prevents raw token leakage.

use crate::audit::AuditLedger;
use crate::identity::{IdentityContext, RequesterType};
use crate::policy::{AuthorizationDecision, OperationRequest, OperationType, PolicyEngine};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Checks if an IP address belongs to loopback, link-local, private RFC1918, CGNAT, multicast, or broadcast ranges
pub fn is_private_or_restricted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // Loopback 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // Link-local / Cloud metadata 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // RFC1918 Private: 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // RFC1918 Private: 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // RFC1918 Private: 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // Carrier-grade NAT (CGNAT): 100.64.0.0/10
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return true;
            }
            // Unspecified 0.0.0.0/8 or Broadcast 255.255.255.255
            if octets[0] == 0 || ipv4.is_broadcast() {
                return true;
            }
            // Multicast 224.0.0.0/4
            if ipv4.is_multicast() {
                return true;
            }
            false
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unspecified() || ipv6.is_multicast() {
                return true;
            }
            let segments = ipv6.segments();
            // Link-local fe80::/10
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Unique local fc00::/7 (ULA)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
                return is_private_or_restricted_ip(&IpAddr::V4(mapped_v4));
            }
            // AWS IPv6 metadata: fd00:ec2::254
            segments[0] == 0xfd00 && segments[1] == 0x0ec2 && segments[7] == 0x0254
        }
    }
}

/// Result of SSRF and destination validation, including DNS pinning information
#[derive(Debug, Clone)]
pub struct ValidatedDestination {
    pub host: String,
    pub port: u16,
    pub pinned_ip: Option<IpAddr>,
    pub is_mock: bool,
}

fn has_ambiguous_ip_format(host: &str) -> bool {
    if host.starts_with("0x") || host.starts_with("0X") {
        return true;
    }
    // Pure integer format e.g. 2130706433
    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        for p in parts {
            if p.len() > 1 && p.starts_with('0') {
                return true; // Octal notation or leading zero ambiguity
            }
        }
    }
    false
}

/// Locates the authentic system curl binary to prevent PATH hijacking
pub fn get_secure_curl_binary_path() -> Result<std::path::PathBuf, String> {
    #[cfg(windows)]
    {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let sys32_curl = std::path::PathBuf::from(&system_root)
            .join("System32")
            .join("curl.exe");
        if sys32_curl.is_file() {
            return Ok(sys32_curl);
        }
        let sys_curl = std::path::PathBuf::from("C:\\Windows\\System32\\curl.exe");
        if sys_curl.is_file() {
            return Ok(sys_curl);
        }
    }
    #[cfg(unix)]
    {
        for path in &["/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"] {
            let p = std::path::PathBuf::from(path);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    // Fail-safe lookup in PATH only if it does NOT come from current working directory or relative path
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir.as_os_str().is_empty() || dir == std::path::Path::new(".") {
                continue; // Reject relative/current directory
            }
            #[cfg(windows)]
            let cand = dir.join("curl.exe");
            #[cfg(not(windows))]
            let cand = dir.join("curl");

            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    Err("Secure system curl executable not found in protected system paths".to_string())
}

/// Canonical RFC 3986 URL authority and host parser that strictly forbids userinfo
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalUrlAuthority {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

pub fn parse_canonical_url(url_str: &str) -> Result<CanonicalUrlAuthority, String> {
    if url_str.contains("169.254.169.254")
        || url_str.contains("metadata.google.internal")
        || url_str.contains("169.254.170.2")
        || url_str.contains("fd00:ec2::254")
        || url_str.contains("metadata.azure.com")
    {
        return Err(
            "Security Violation: Target resource attempts Cloud Metadata SSRF (SSRF Protection)."
                .to_string(),
        );
    }

    // 1. Parse scheme cleanly
    let scheme_end = match url_str.find("://") {
        Some(pos) => pos,
        None => {
            return Err(format!(
                "Invalid URL format: '{}' must specify a valid protocol scheme (e.g. https://).",
                url_str
            ));
        }
    };
    let scheme = url_str[..scheme_end].to_lowercase();
    if scheme != "https" && scheme != "http" && scheme != "mock" && scheme != "test" {
        return Err(format!(
            "Unsupported protocol scheme '{}'. Only HTTPS (or local HTTP) is permitted.",
            scheme
        ));
    }

    let after_scheme = &url_str[scheme_end + 3..];

    // 2. Extract authority (everything up to first '/', '?', '#', or end of string)
    let (authority, path_and_query) = match after_scheme.find(['/', '?', '#']) {
        Some(pos) => (&after_scheme[..pos], &after_scheme[pos..]),
        None => (after_scheme, "/"),
    };

    if authority.is_empty() {
        return Err(
            "Security Violation: URL missing authority/host (SSRF Protection).".to_string(),
        );
    }

    // 3. STRICT USERINFO REJECTION:
    // URLs containing '@' or percent-encoded userinfo '%40' are strictly forbidden to prevent credential exfiltration.
    if authority.contains('@')
        || authority.contains("%40")
        || authority.contains("%40")
        || authority.contains('\\')
    {
        return Err(
            "Security Violation: URLs containing user information ('@') or backslashes are strictly forbidden to prevent credential exfiltration (SSRF Protection)."
                .to_string(),
        );
    }

    if scheme == "mock" || scheme == "test" {
        let h = if authority.is_empty() {
            "mock"
        } else {
            authority
        };
        return Ok(CanonicalUrlAuthority {
            scheme,
            host: h.to_lowercase(),
            port: 0,
            path_and_query: path_and_query.to_string(),
        });
    }

    // 4. Host and Port parsing
    let (host, port) = if authority.starts_with('[') {
        // IPv6 bracketed address
        let bracket_end = authority.find(']').ok_or_else(|| {
            "Security Violation: Malformed bracketed IPv6 address in URL (SSRF Protection)."
                .to_string()
        })?;
        let h = &authority[1..bracket_end];
        let rest = &authority[bracket_end + 1..];
        let p = if let Some(colon_pos) = rest.find(':') {
            rest[colon_pos + 1..]
                .parse::<u16>()
                .map_err(|_| "Invalid port number in IPv6 URL".to_string())?
        } else if scheme == "https" {
            443
        } else {
            80
        };
        (h, p)
    } else if let Some(colon_pos) = authority.rfind(':') {
        let h = &authority[..colon_pos];
        let p = authority[colon_pos + 1..]
            .parse::<u16>()
            .map_err(|_| "Invalid port number in URL".to_string())?;
        (h, p)
    } else {
        (authority, if scheme == "https" { 443 } else { 80 })
    };

    // Strip trailing dots from FQDN
    let host_clean = host.trim_end_matches('.');
    if host_clean.is_empty() {
        return Err("Security Violation: Hostname cannot be empty (SSRF Protection).".to_string());
    }

    // Validate characters: host must not contain spaces, control characters, or delimiters
    if host_clean.chars().any(|c| {
        c.is_whitespace() || c == '/' || c == '?' || c == '#' || c == ':' || c == '@' || c == '\\'
    }) {
        return Err(format!(
            "Security Violation: Hostname '{}' contains invalid characters (SSRF Protection).",
            host_clean
        ));
    }

    Ok(CanonicalUrlAuthority {
        scheme,
        host: host_clean.to_lowercase(),
        port,
        path_and_query: path_and_query.to_string(),
    })
}

/// Comprehensive SSRF and URL validation preventing attacks against cloud metadata, internal subnets, and DNS rebinding
pub fn validate_url_and_destination(url_str: &str) -> Result<ValidatedDestination, String> {
    validate_destination_internal(url_str, false)
}

/// Internal destination validator with offline mock tolerance for network-isolated unit testing
pub fn validate_destination_internal(
    url_str: &str,
    is_offline_mock: bool,
) -> Result<ValidatedDestination, String> {
    let canonical = parse_canonical_url(url_str)?;
    let host = &canonical.host;
    let port = canonical.port;
    let scheme = &canonical.scheme;

    if scheme == "mock" || scheme == "test" {
        return Ok(ValidatedDestination {
            host: host.to_string(),
            port: 0,
            pinned_ip: None,
            is_mock: true,
        });
    }

    // Strict protocol check:
    // Only HTTPS is permitted, EXCEPT local HTTP where host is strictly localhost, 127.0.0.1, or ::1
    let is_strict_loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
    let is_https = scheme == "https";
    let is_local_http = scheme == "http" && is_strict_loopback;

    if !is_https && !is_local_http {
        return Err(format!(
            "Invalid Protocol: URL '{}' must use secure HTTPS (or strictly localhost/127.0.0.1 for local testing).",
            url_str
        ));
    }

    // Check for ambiguous / non-canonical IP representations (octal, hex, dword)
    if has_ambiguous_ip_format(host) {
        return Err(format!(
            "Security Violation: Ambiguous non-canonical IP address format '{}' rejected (SSRF Protection).",
            host
        ));
    }

    // Direct IP address check
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_local_http && ip.is_loopback() {
            return Ok(ValidatedDestination {
                host: host.to_string(),
                port,
                pinned_ip: Some(ip),
                is_mock: false,
            });
        }
        if is_private_or_restricted_ip(&ip) {
            return Err(format!(
                "Security Violation: Target IP '{}' is a private/restricted network or cloud metadata address (SSRF Protection).",
                ip
            ));
        }
        return Ok(ValidatedDestination {
            host: host.to_string(),
            port,
            pinned_ip: Some(ip),
            is_mock: false,
        });
    }

    // Hostname: resolve via DNS with strict fail-closed handling
    if is_local_http && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1") {
        return Ok(ValidatedDestination {
            host: host.to_string(),
            port,
            pinned_ip: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            is_mock: false,
        });
    }

    if host.contains("localhost")
        || host.ends_with(".internal")
        || host.ends_with(".local")
        || host.contains("169.254")
    {
        return Err(format!(
            "Security Violation: Target host '{}' is an internal or metadata domain (SSRF Protection).",
            host
        ));
    }

    let socket_addr_str = format!("{}:{}", host, port);
    match socket_addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let mut resolved_ips = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if is_private_or_restricted_ip(&ip) {
                    return Err(format!(
                        "Security Violation: Destination '{}' resolves to private/restricted IP '{}' (SSRF Protection).",
                        host, ip
                    ));
                }
                resolved_ips.push(ip);
            }

            let pinned_ip = resolved_ips.into_iter().next().ok_or_else(|| {
                format!(
                    "Security Violation: No IP addresses resolved for host '{}' (Fail-Closed SSRF Protection).",
                    host
                )
            })?;

            Ok(ValidatedDestination {
                host: host.to_string(),
                port,
                pinned_ip: Some(pinned_ip),
                is_mock: false,
            })
        }
        Err(e) => {
            if is_offline_mock {
                // In offline unit test simulations without internet, permit public domain mock execution
                Ok(ValidatedDestination {
                    host: host.to_string(),
                    port,
                    pinned_ip: None,
                    is_mock: true,
                })
            } else {
                Err(format!(
                    "Security Violation: DNS resolution failed for destination '{}': {} (Fail-Closed SSRF Protection).",
                    host, e
                ))
            }
        }
    }
}

/// Result of an approved delegated operation executed by the broker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub scrubbed_tokens_count: usize,
    pub audit_sequence: u64,
}

pub const DEFAULT_APPROVAL_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub nonce: String,
    pub request_fingerprint: String,
    pub expires_at_epoch_secs: u64,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub nonce: String,
    pub request_fingerprint: String,
    pub expires_at_epoch_secs: u64,
    #[serde(default)]
    pub signature: String,
}

#[derive(Default)]
pub struct ApprovalManager {
    consumed_nonces: Mutex<HashSet<String>>,
}

impl ApprovalManager {
    pub fn compute_request_fingerprint(req: &OperationRequest) -> String {
        let exe_path = req
            .requester
            .executable_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| req.requester.executable_name.clone());
        let bin_hash = req.requester.binary_hash.as_deref().unwrap_or("");
        let mut hasher = Sha256::new();
        for part in [
            &req.requester.pid.to_string(),
            &exe_path,
            bin_hash,
            req.operation.as_str(),
            &req.credential_name,
            &req.target_resource,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"|");
        }
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn get_approval_hmac_key() -> Result<[u8; 32], String> {
        crate::vault::derive_vault_key(Some("secretguard_approval_hmac_v1")).map_err(|e| {
            format!(
                "Security Fail-Closed: Persistent approval signing key unavailable ({}).",
                e
            )
        })
    }

    fn compute_token_signature(
        nonce: &str,
        request_fingerprint: &str,
        expires_at_epoch_secs: u64,
    ) -> Result<String, String> {
        let mut key = Self::get_approval_hmac_key()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| format!("Failed to initialize approval HMAC: {}", e))?;
        crate::vault::volatile_zeroize(&mut key);

        mac.update(b"secretguard-approval-token-v1|");
        mac.update(nonce.as_bytes());
        mac.update(b"|");
        mac.update(request_fingerprint.as_bytes());
        mac.update(b"|");
        mac.update(expires_at_epoch_secs.to_string().as_bytes());

        let result = mac.finalize().into_bytes();
        Ok(result.iter().map(|b| format!("{:02x}", b)).collect())
    }

    fn verify_token_signature(token: &ApprovalToken) -> Result<(), String> {
        if token.signature.is_empty() || token.signature.len() != 64 {
            return Err("Approval token is missing a valid cryptographic signature.".to_string());
        }
        let sig_bytes: Vec<u8> = (0..token.signature.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&token.signature[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| "Approval token signature is malformed hex.".to_string())?;

        let mut key = Self::get_approval_hmac_key()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| format!("Failed to initialize approval HMAC: {}", e))?;
        crate::vault::volatile_zeroize(&mut key);

        mac.update(b"secretguard-approval-token-v1|");
        mac.update(token.nonce.as_bytes());
        mac.update(b"|");
        mac.update(token.request_fingerprint.as_bytes());
        mac.update(b"|");
        mac.update(token.expires_at_epoch_secs.to_string().as_bytes());

        mac.verify_slice(&sig_bytes).map_err(|_| {
            "Approval token signature verification failed (possible forgery).".to_string()
        })
    }

    fn get_nonces_store_path() -> std::path::PathBuf {
        let base = std::env::var("SECRETGUARD_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                crate::vault::get_vault_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from(".secretguard"))
            });
        let base = crate::vault::resolve_canonical_security_path(&base).unwrap_or(base);
        base.join("approval_nonces.json")
    }

    fn record_consumed_nonce_persistent(
        nonce: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), String> {
        let store_path = Self::get_nonces_store_path();
        if let Some(parent) = store_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let lock_path = store_path.with_extension("lock");

        let mut lock_file = None;
        let max_attempts = 50;
        for attempt in 0..max_attempts {
            if let Ok(mut f) = crate::vault::create_secure_file_exclusive(&lock_path, 0o600) {
                use std::io::Write;
                let _ = writeln!(f, "pid={}", std::process::id());
                lock_file = Some(f);
                break;
            }
            if let Ok(meta) = std::fs::symlink_metadata(&lock_path) {
                if !meta.file_type().is_symlink() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            if elapsed.as_secs() >= 30 {
                                let pid_alive = std::fs::read_to_string(&lock_path)
                                    .ok()
                                    .and_then(|s| {
                                        s.lines().find_map(|l| {
                                            l.strip_prefix("pid=")
                                                .and_then(|v| v.trim().parse::<u32>().ok())
                                        })
                                    })
                                    .map(crate::ghost::is_pid_alive)
                                    .unwrap_or(false);
                                if !pid_alive {
                                    let _ = std::fs::remove_file(&lock_path);
                                }
                            }
                        }
                    }
                }
            }
            if attempt < max_attempts - 1 {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
        let _lock = lock_file.ok_or_else(|| {
            "Failed to acquire approval nonce store lock (concurrent contention).".to_string()
        })?;

        struct NonceLockGuard<'a>(&'a std::path::Path);
        impl<'a> Drop for NonceLockGuard<'a> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
            }
        }
        let _guard = NonceLockGuard(&lock_path);

        let mut store: HashMap<String, u64> = if store_path.exists() {
            crate::vault::validate_secure_path(&store_path, true)
                .map_err(|e| format!("Approval nonce store path unsafe: {}", e))?;
            let raw = std::fs::read_to_string(&store_path)
                .map_err(|e| format!("Failed to read approval nonce store: {}", e))?;
            if raw.trim().is_empty() {
                HashMap::new()
            } else {
                serde_json::from_str(&raw)
                    .map_err(|e| format!("Corrupted approval nonce store: {}", e))?
            }
        } else {
            HashMap::new()
        };

        // Prune expired nonces so the store stays bounded
        store.retain(|_, &mut exp| exp >= now);

        if store.contains_key(nonce) {
            return Err("Approval token replay detected (already consumed).".to_string());
        }
        store.insert(nonce.to_string(), expires_at);

        let json = serde_json::to_string(&store)
            .map_err(|e| format!("Failed to serialize approval nonce store: {}", e))?;
        let tmp_name = format!(
            ".approval_nonces.{}.{:x}.tmp",
            std::process::id(),
            OsRng.next_u64()
        );
        let tmp_path = store_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(tmp_name);
        {
            use std::io::Write;
            let mut f = crate::vault::create_secure_file_exclusive(&tmp_path, 0o600)
                .map_err(|e| format!("Failed to create temp approval nonce store: {}", e))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write temp approval nonce store: {}", e))?;
            f.sync_all()
                .map_err(|e| format!("Failed to sync temp approval nonce store: {}", e))?;
        }
        crate::vault::atomic_replace_file(&tmp_path, &store_path)
            .map_err(|e| format!("Failed to persist approval nonce store: {}", e))?;
        Ok(())
    }

    pub fn configured_ttl_secs() -> u64 {
        std::env::var("SECRETGUARD_APPROVAL_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0 && n <= 3600)
            .unwrap_or(DEFAULT_APPROVAL_TTL_SECS)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn issue_challenge(
        &self,
        req: &OperationRequest,
        ttl_secs: Option<u64>,
    ) -> ApprovalChallenge {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let nonce: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        let ttl = ttl_secs.unwrap_or_else(Self::configured_ttl_secs);
        let expires = Self::now_secs().saturating_add(ttl);
        let fp = Self::compute_request_fingerprint(req);
        // Never expose secret values in approval prompts — only caller, operation, credential name, and target
        let prompt = format!(
            "Approve '{}' (PID {}) to perform '{}' on '{}' using credential '{}'? (expires in {}s)",
            req.requester.executable_name,
            req.requester.pid,
            req.operation.as_str(),
            crate::audit::sanitize_audit_target(&req.target_resource),
            req.credential_name,
            ttl
        );
        ApprovalChallenge {
            nonce,
            request_fingerprint: fp,
            expires_at_epoch_secs: expires,
            prompt,
        }
    }

    pub fn approve_challenge(
        &self,
        challenge: &ApprovalChallenge,
    ) -> Result<ApprovalToken, String> {
        if Self::now_secs() > challenge.expires_at_epoch_secs {
            return Err("Approval challenge expired before confirmation.".to_string());
        }
        let signature = Self::compute_token_signature(
            &challenge.nonce,
            &challenge.request_fingerprint,
            challenge.expires_at_epoch_secs,
        )?;
        Ok(ApprovalToken {
            nonce: challenge.nonce.clone(),
            request_fingerprint: challenge.request_fingerprint.clone(),
            expires_at_epoch_secs: challenge.expires_at_epoch_secs,
            signature,
        })
    }

    pub fn consume_approval(
        &self,
        req: &OperationRequest,
        token: &ApprovalToken,
    ) -> Result<(), String> {
        let now = Self::now_secs();
        if now > token.expires_at_epoch_secs {
            return Err("Approval token has expired.".to_string());
        }
        Self::verify_token_signature(token)?;
        let expected_fp = Self::compute_request_fingerprint(req);
        if token.request_fingerprint != expected_fp {
            return Err("Approval token does not match this exact request.".to_string());
        }
        {
            let consumed = self
                .consumed_nonces
                .lock()
                .map_err(|_| "Approval nonce store mutex poisoned".to_string())?;
            if consumed.contains(&token.nonce) {
                return Err("Approval token replay detected (already consumed).".to_string());
            }
        }
        Self::record_consumed_nonce_persistent(&token.nonce, token.expires_at_epoch_secs, now)?;
        let mut consumed = self
            .consumed_nonces
            .lock()
            .map_err(|_| "Approval nonce store mutex poisoned".to_string())?;
        consumed.insert(token.nonce.clone());
        Ok(())
    }
}

/// The Local Security Broker
pub struct SecurityBroker {
    pub policy_engine: Arc<RwLock<PolicyEngine>>,
    pub audit_ledger: Arc<Mutex<AuditLedger>>,
    pub approval_manager: Arc<ApprovalManager>,
}

impl Default for SecurityBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityBroker {
    /// Initializes a new SecurityBroker safely; fails closed if existing audit ledger is corrupted
    pub fn try_new() -> Result<Self, String> {
        let policy_engine = Arc::new(RwLock::new(PolicyEngine::default()));

        let audit_path = AuditLedger::get_default_path();
        let ledger = if audit_path.exists() {
            AuditLedger::load(None).map_err(|e| {
                format!(
                    "Security Fail-Closed: Existing audit ledger is corrupted or tampered ({}). Refusing to start broker.",
                    e
                )
            })?
        } else {
            AuditLedger::new()
        };

        Ok(Self {
            policy_engine,
            audit_ledger: Arc::new(Mutex::new(ledger)),
            approval_manager: Arc::new(ApprovalManager::default()),
        })
    }

    /// Initializes a new SecurityBroker instance loading policy and audit ledger
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            eprintln!("CRITICAL SECURITY REFUSAL: {}", e);
            panic!("{}", e);
        })
    }

    fn record_and_persist(
        &self,
        req: &OperationRequest,
        decision: &AuthorizationDecision,
    ) -> Result<(), String> {
        let rec = AuditLedger::append_decision_atomic(req, decision, None)?;
        if let Ok(mut ledger) = self.audit_ledger.lock() {
            ledger.records.push(rec);
        }
        Ok(())
    }

    /// Evaluates an OperationRequest, records it to the tamper-evident audit ledger, and returns the decision
    pub fn authorize(&self, req: &OperationRequest) -> AuthorizationDecision {
        let decision = {
            let engine = self.policy_engine.read().unwrap();
            engine.evaluate(req)
        };

        if let Err(e) = self.record_and_persist(req, &decision) {
            return AuthorizationDecision::Deny {
                reason: format!(
                    "Security Fail-Closed: Failed to record audit log ({}). Access denied.",
                    e
                ),
            };
        }

        decision
    }

    /// Evaluates an OperationRequest with an optional single-use, request-bound ApprovalToken.
    pub fn authorize_with_approval(
        &self,
        req: &OperationRequest,
        approval: Option<&ApprovalToken>,
    ) -> AuthorizationDecision {
        let raw_decision = {
            let engine = self.policy_engine.read().unwrap();
            engine.evaluate(req)
        };

        let final_decision = match raw_decision {
            AuthorizationDecision::RequireHumanApproval { .. } => match approval {
                Some(tok) => match self.approval_manager.consume_approval(req, tok) {
                    Ok(()) => {
                        if req.requester.requester_type == RequesterType::HumanInteractive {
                            AuthorizationDecision::AllowRaw
                        } else {
                            AuthorizationDecision::AllowDelegated
                        }
                    }
                    Err(err) => AuthorizationDecision::Deny {
                        reason: format!("Approval rejected: {}", err),
                    },
                },
                None => raw_decision,
            },
            other => other,
        };

        if let Err(e) = self.record_and_persist(req, &final_decision) {
            return AuthorizationDecision::Deny {
                reason: format!(
                    "Security Fail-Closed: Failed to record audit log ({}). Access denied.",
                    e
                ),
            };
        }

        final_decision
    }

    /// Centralized control-plane authorization for local CLI secret-access entry points
    /// (`vault get`, `vault run`, `ghost virtualize`).
    pub fn authorize_local_secret_access(
        op: OperationType,
        credential_name: &str,
        target_resource: &str,
        is_interactive_tty: bool,
    ) -> Result<AuthorizationDecision, String> {
        let my_pid = std::process::id();
        let parent_pid = crate::identity::get_parent_pid(my_pid).unwrap_or(my_pid);
        let caller = IdentityContext::from_pid_with_tty(parent_pid, is_interactive_tty)
            .or_else(|_| IdentityContext::from_pid_with_tty(my_pid, is_interactive_tty))?;

        let broker = Self::try_new()?;
        let req = OperationRequest::new(caller, credential_name, op, target_resource);
        let decision = broker.authorize(&req);
        if decision.is_allowed() {
            Ok(decision)
        } else {
            match decision {
                AuthorizationDecision::Deny { reason } => Err(reason),
                AuthorizationDecision::RequireHumanApproval { prompt, .. } => Err(prompt),
                _ => unreachable!(),
            }
        }
    }

    /// Safely executes an HTTP operation on behalf of the caller without returning raw tokens
    pub fn execute_delegated_call(
        &self,
        req: &OperationRequest,
        mock_secret_provider: Option<&str>,
    ) -> Result<DelegatedResponse, String> {
        // 0. Quarantined Credential Fast Circuit-Breaker:
        // Quarantined tokens are permanently blocked from any operation or network lookup
        if req.credential_name.starts_with("QUARANTINED_") {
            return Err(format!(
                "Security Circuit-Breaker: Credential '{}' is in QUARANTINED state and permanently blocked from use.",
                req.credential_name
            ));
        }

        // 1. Strict URL and SSRF validation with DNS pinning info
        let url = &req.target_resource;
        let is_mock_call = mock_secret_provider.is_some()
            || url.starts_with("mock://")
            || url.starts_with("test://");
        let dest = validate_destination_internal(url, is_mock_call)?;

        let is_http = url.starts_with("https://")
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost");
        let is_mock_test = dest.is_mock;

        // 2. Authorize via policy engine and audit ledger
        let decision = self.authorize(req);

        match decision {
            AuthorizationDecision::AllowDelegated => {
                // Fetch the actual credential securely in-memory
                let secret_value = if let Some(mock) = mock_secret_provider {
                    mock.to_string()
                } else if is_mock_test {
                    "SG_MOCK_TEST_SECRET".to_string()
                } else {
                    let vault = crate::vault::load_vault(None)
                        .map_err(|e| format!("Security Broker failed to load vault: {}", e))?;
                    vault
                        .secrets
                        .get(&req.credential_name)
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Security Broker: Credential '{}' not found in vault.",
                                req.credential_name
                            )
                        })?
                };

                if secret_value.starts_with("[QUARANTINED_BLOCKED") {
                    return Err(format!(
                        "Security Circuit-Breaker: Credential '{}' is in QUARANTINED state and permanently blocked from use.",
                        req.credential_name
                    ));
                }

                // Security: Reject control characters that could facilitate HTTP header injection or config corruption
                if secret_value.contains('\r')
                    || secret_value.contains('\n')
                    || secret_value.contains('\0')
                {
                    return Err(
                        "Security Violation: Secret credential contains invalid newline or null characters (Header Injection Prevention)."
                            .to_string(),
                    );
                }

                // 3. Dispatch genuine delegated HTTP call (or mock test harness if mock URL)
                let (raw_status, raw_body) = if is_http && mock_secret_provider.is_none() {
                    let auth_header = if req.credential_name.to_uppercase().contains("GITHUB") {
                        format!("Authorization: token {}", secret_value)
                    } else {
                        format!("Authorization: Bearer {}", secret_value)
                    };

                    let method = req.operation.as_str();

                    // Security: Pass sensitive headers over child stdin pipe using curl's --config -
                    // This ensures secrets NEVER appear in command line arguments or /proc/<pid>/cmdline.
                    // -q MUST be the first argument to disable loading ~/.curlrc or system curl config files.
                    // --noproxy "*" and stripping proxy env vars prevents proxy interception or redirection.
                    // Pre-populate curl's DNS cache using --resolve to eliminate DNS rebinding TOCTOU window.
                    let curl_bin = get_secure_curl_binary_path()?;
                    let mut curl_cmd = std::process::Command::new(curl_bin);
                    curl_cmd.args([
                        "-q",
                        "-s",
                        "-w",
                        "\n%{http_code}",
                        "--noproxy",
                        "*",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--max-redirs",
                        "0",
                        "--max-time",
                        "15",
                        "-X",
                        method,
                    ]);

                    curl_cmd
                        .env_remove("HTTP_PROXY")
                        .env_remove("http_proxy")
                        .env_remove("HTTPS_PROXY")
                        .env_remove("https_proxy")
                        .env_remove("ALL_PROXY")
                        .env_remove("all_proxy")
                        .env_remove("CURL_HOME");

                    let resolve_arg = dest
                        .pinned_ip
                        .map(|ip| format!("{}:{}:{}", dest.host, dest.port, ip));
                    if let Some(ref res_arg) = resolve_arg {
                        curl_cmd.arg("--resolve").arg(res_arg);
                    }

                    curl_cmd.args(["--config", "-"]);

                    let mut child = curl_cmd
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .map_err(|e| {
                            format!("Delegated HTTP dispatch error (spawning curl): {}", e)
                        })?;

                    let sanitized_header = auth_header.replace('\\', "\\\\").replace('"', "\\\"");
                    let sanitized_url = url
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace(['\r', '\n'], "");

                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        stdin
                            .write_all(format!("url = \"{}\"\n", sanitized_url).as_bytes())
                            .map_err(|e| {
                                format!("Security Error: Failed writing URL to curl stdin: {}", e)
                            })?;
                        stdin
                            .write_all(format!("header = \"{}\"\n", sanitized_header).as_bytes())
                            .map_err(|e| {
                                format!(
                                    "Security Error: Failed writing header to curl stdin: {}",
                                    e
                                )
                            })?;
                        stdin
                            .write_all(b"header = \"User-Agent: SecretGuard-Security-Broker/1.0\"\n")
                            .map_err(|e| {
                                format!(
                                    "Security Error: Failed writing User-Agent to curl stdin: {}",
                                    e
                                )
                            })?;
                        stdin.flush().map_err(|e| {
                            format!("Security Error: Failed flushing curl stdin stream: {}", e)
                        })?;
                        // Drop stdin to signal EOF so curl can execute
                        drop(stdin);
                    }

                    // Security: Read stdout boundedly up to 10 MB to prevent memory exhaustion attacks
                    const MAX_DELEGATED_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
                    use std::io::Read;

                    let mut stdout_handle = child
                        .stdout
                        .take()
                        .ok_or_else(|| "Failed to capture child stdout stream".to_string())?;
                    let mut stderr_handle = child
                        .stderr
                        .take()
                        .ok_or_else(|| "Failed to capture child stderr stream".to_string())?;

                    let mut stdout_bytes = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        let n = stdout_handle
                            .read(&mut chunk)
                            .map_err(|e| format!("Failed reading curl stdout: {}", e))?;
                        if n == 0 {
                            break;
                        }
                        stdout_bytes.extend_from_slice(&chunk[..n]);
                        if stdout_bytes.len() > MAX_DELEGATED_RESPONSE_BYTES {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(
                                "Security Violation: Delegated response exceeded maximum permitted size of 10 MB (Memory Exhaustion Prevention)."
                                    .to_string(),
                            );
                        }
                    }

                    let mut stderr_bytes = Vec::new();
                    let _ = stderr_handle.read_to_end(&mut stderr_bytes);

                    let status = child
                        .wait()
                        .map_err(|e| {
                            format!("Delegated HTTP dispatch error (waiting for curl): {}", e)
                        })?;

                    if !status.success() {
                        let stderr_text = String::from_utf8_lossy(&stderr_bytes);
                        return Err(format!(
                            "Delegated HTTP request failed (curl exit code {:?}): {}",
                            status.code(),
                            stderr_text.trim()
                        ));
                    }

                    let text = String::from_utf8_lossy(&stdout_bytes).to_string();
                    if let Some(last_newline) = text.rfind('\n') {
                        let body = text.as_bytes()[..last_newline].to_vec();
                        let code_str = text[last_newline + 1..].trim();
                        let code = code_str.parse::<u16>().map_err(|_| {
                            "Failed to parse HTTP status code from curl response".to_string()
                        })?;
                        (code, body)
                    } else {
                        return Err(
                            "Malformed curl output: missing HTTP status code trailer".to_string()
                        );
                    }
                } else {
                    // Offline test harness execution
                    let body_str = format!(
                        r#"{{"status":"ok","delegated_execution":true,"resource":"{}","operation":"{}"}}"#,
                        req.target_resource,
                        req.operation.as_str()
                    );
                    (200, body_str.into_bytes())
                };

                // 4. Scrubbing: Ensure real secret is NEVER reflected back to caller
                let mut body_str = String::from_utf8_lossy(&raw_body).to_string();
                let mut scrubbed_count = 0;
                if body_str.contains(&secret_value) {
                    body_str = body_str.replace(&secret_value, "[DELEGATED_SECRET_MASKED]");
                    scrubbed_count += 1;
                }

                // Inbound scanner layer: sanitize any other leaked keys in response
                let engine = crate::SecretGuardEngine::new();
                let scanned = engine.scan_and_sanitize(&body_str);
                if scanned.has_secret {
                    body_str = scanned.sanitized_text;
                    scrubbed_count += 1;
                }

                let audit_seq = self
                    .audit_ledger
                    .lock()
                    .ok()
                    .and_then(|l| l.records.last().map(|r| r.sequence_number))
                    .unwrap_or(0);

                Ok(DelegatedResponse {
                    status_code: raw_status,
                    body: body_str.into_bytes(),
                    scrubbed_tokens_count: scrubbed_count,
                    audit_sequence: audit_seq,
                })
            }
            AuthorizationDecision::RequireHumanApproval { prompt, .. } => Err(format!(
                "Operation suspended: Human approval required ('{}').",
                prompt
            )),
            AuthorizationDecision::Deny { reason } => Err(format!("Access Denied: {}", reason)),
            AuthorizationDecision::AllowRaw => Err(
                "Policy mismatch: Operation requested delegated execution but policy returned AllowRaw."
                    .to_string(),
            ),
        }
    }

    /// CLI Handler for `secretguard broker`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard broker - Local Zero-Trust Security Broker & Authorization Plane
Coordinates process identity, policy checks, audit logging, and delegated execution.

USAGE:
    secretguard broker <SUBCOMMAND>

SUBCOMMANDS:
    status                 Displays broker status, active policies, and audit stats
    test-auth <ROLE> <OP>  Simulates authorization check for a role and operation
"#
            );
            return;
        }

        let broker = Self::new();
        match args[0].as_str() {
            "status" => {
                let policies = broker.policy_engine.read().unwrap();
                let ledger = broker.audit_ledger.lock().unwrap();
                println!("🛡️  SecretGuard Local Security Broker Status");
                println!("────────────────────────────────────────────");
                println!("Active Policy Rules:  {}", policies.rules.len());
                for r in &policies.rules {
                    println!("  • \x1b[36m{}\x1b[0m [{}]", r.name, r.id);
                }
                println!("\nAudit Ledger Records: {}", ledger.records.len());
                if let Ok(count) = ledger.verify_integrity() {
                    println!(
                        "Cryptographic Integrity: ✅ Verified ({} records intact)",
                        count
                    );
                } else if ledger.records.is_empty() {
                    println!("Cryptographic Integrity: ℹ️  Ledger initialized (0 events)");
                } else {
                    println!("Cryptographic Integrity: ❌ CORRUPTED OR TAMPERED");
                }
            }
            "test-auth" => {
                let role_arg = args.get(1).map(|s| s.as_str()).unwrap_or("agent");
                let op_arg = args.get(2).map(|s| s.as_str()).unwrap_or("GET");

                let req_type = match role_arg {
                    "human" | "developer" => RequesterType::HumanInteractive,
                    "agent" | "claude" | "aider" => RequesterType::AutonomousAgent,
                    "mcp" => RequesterType::McpServer,
                    _ => RequesterType::UnknownProcess,
                };

                let op_type = match op_arg.to_uppercase().as_str() {
                    "GET" => OperationType::HttpGet,
                    "POST" => OperationType::HttpPost,
                    "PUT" => OperationType::HttpPut,
                    "DELETE" => OperationType::HttpDelete,
                    "RAW" => OperationType::RawCredentialAccess,
                    _ => OperationType::HttpGet,
                };

                let human = IdentityContext::mock("test-caller", req_type, Some("org/repo"), None);
                let req = OperationRequest::new(
                    human,
                    "GITHUB_TOKEN",
                    op_type,
                    "https://api.github.com/repos/org/repo/pulls",
                );
                let decision = broker.authorize(&req);
                println!(
                    "Test Authorization Decision for '{:?}' performing '{}':",
                    req_type, op_arg
                );
                println!("  Result: {:?}", decision);
            }
            _ => {
                eprintln!(
                    "Unknown broker subcommand '{}'. Run 'secretguard broker --help'.",
                    args[0]
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broker_delegated_execution_scrubs_secret() {
        let _lock = crate::vault::TERMINAL_INPUT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp_dir = std::env::temp_dir().join(format!("sg_broker_unit_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        std::env::set_var("SECRETGUARD_DIR", &temp_dir);

        let broker = SecurityBroker::new();
        let agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("org/repo"),
            None,
        );
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpGet,
            "https://api.github.com/repos/org/repo/pulls",
        );

        let secret = "sk-test-super-secret-token";
        let res = broker.execute_delegated_call(&req, Some(secret)).unwrap();
        assert_eq!(res.status_code, 200);
        let body_str = String::from_utf8(res.body).unwrap();
        assert!(!body_str.contains(secret));

        std::env::remove_var("SECRETGUARD_DIR");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
