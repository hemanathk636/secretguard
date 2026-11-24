//! Tamper-Evident Security Audit Ledger for SecretGuard
//! Cryptographically hash-chained, monotonically ordered, append-only security logs.

use crate::identity::RequesterType;
use crate::policy::{AuthorizationDecision, OperationRequest};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

static GLOBAL_AUDIT_KEY: std::sync::RwLock<Option<[u8; 32]>> = std::sync::RwLock::new(None);

/// Returns or initializes local HMAC signing key for tamper-proof audit verification
pub fn get_or_create_audit_key() -> Result<[u8; 32], std::io::Error> {
    if let Ok(guard) = GLOBAL_AUDIT_KEY.read() {
        if let Some(key) = *guard {
            return Ok(key);
        }
    }

    let mut guard = GLOBAL_AUDIT_KEY
        .write()
        .map_err(|_| std::io::Error::other("Audit key lock poisoned"))?;
    if let Some(key) = *guard {
        return Ok(key);
    }

    let dir = crate::vault::get_vault_dir()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    fs::create_dir_all(&dir)?;
    let key_path = dir.join("audit.hmac.key");
    if key_path.exists() {
        let meta = fs::symlink_metadata(&key_path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Security Alert: audit.hmac.key is an untrusted symlink",
            ));
        }
        let data = fs::read(&key_path)?;
        if data.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&data);
            *guard = Some(k);
            return Ok(k);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Security Alert: Corrupt audit.hmac.key file: expected 32 bytes, found {}",
                    data.len()
                ),
            ));
        }
    }

    // Fail-Closed: Generate 32-byte CSPRNG key and persist exclusively with 0o600.
    // If creation or writing fails, fail closed with Err - never return an ephemeral in-memory key!
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    let mut file = crate::vault::create_secure_file_exclusive(&key_path, 0o600)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
    file.write_all(&k)?;
    file.sync_all()?;

    *guard = Some(k);
    Ok(k)
}

#[cfg(test)]
pub fn set_test_audit_key(key: [u8; 32]) {
    let mut guard = GLOBAL_AUDIT_KEY.write().unwrap();
    *guard = Some(key);
}

#[cfg(test)]
pub fn clear_test_audit_key() {
    let mut guard = GLOBAL_AUDIT_KEY.write().unwrap();
    *guard = None;
}

/// Immutable, hash-chained record representing a security authorization event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence_number: u64,
    pub timestamp_epoch_secs: u64,
    pub requester_pid: u32,
    pub requester_name: String,
    pub requester_type: RequesterType,
    pub credential_name: String,
    pub operation: String,
    pub target_resource: String,
    pub decision: String,
    pub prev_record_hash: String,
    pub record_hash: String,
}

impl AuditRecord {
    /// Computes cryptographically keyed HMAC-SHA256 across record attributes
    /// Uses canonical length-delimited framing to prevent field concatenation ambiguity.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_keyed_hash(
        key: &[u8],
        seq: u64,
        timestamp: u64,
        pid: u32,
        name: &str,
        req_type: RequesterType,
        cred: &str,
        op: &str,
        target: &str,
        decision: &str,
        prev_hash: &str,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        let req_type_str = format!("{:?}", req_type);

        fn write_delimited(mac: &mut HmacSha256, data: &[u8]) {
            mac.update(&(data.len() as u64).to_le_bytes());
            mac.update(data);
        }

        mac.update(&seq.to_le_bytes());
        mac.update(&timestamp.to_le_bytes());
        mac.update(&pid.to_le_bytes());
        write_delimited(&mut mac, name.as_bytes());
        write_delimited(&mut mac, req_type_str.as_bytes());
        write_delimited(&mut mac, cred.as_bytes());
        write_delimited(&mut mac, op.as_bytes());
        write_delimited(&mut mac, target.as_bytes());
        write_delimited(&mut mac, decision.as_bytes());
        write_delimited(&mut mac, prev_hash.as_bytes());

        let result = mac.finalize();
        let bytes = result.into_bytes();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Computes deterministic hash across record attributes using persisted audit key; fails closed
    #[allow(clippy::too_many_arguments)]
    pub fn compute_hash(
        seq: u64,
        timestamp: u64,
        pid: u32,
        name: &str,
        req_type: RequesterType,
        cred: &str,
        op: &str,
        target: &str,
        decision: &str,
        prev_hash: &str,
    ) -> Result<String, std::io::Error> {
        let key = get_or_create_audit_key()?;
        Ok(Self::compute_keyed_hash(
            &key, seq, timestamp, pid, name, req_type, cred, op, target, decision, prev_hash,
        ))
    }
}

/// Verification failure detail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditIntegrityError {
    EmptyLedger,
    KeyError(String),
    SequenceMismatch {
        index: usize,
        expected: u64,
        found: u64,
    },
    TimestampRegression {
        index: usize,
        prev_timestamp: u64,
        found_timestamp: u64,
    },
    PrevHashMismatch {
        index: usize,
        expected_prev_hash: String,
        found_prev_hash: String,
    },
    HashVerificationFailed {
        index: usize,
        stored_hash: String,
        computed_hash: String,
    },
}

impl std::fmt::Display for AuditIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditIntegrityError::EmptyLedger => write!(f, "Audit ledger contains zero records."),
            AuditIntegrityError::KeyError(err) => write!(f, "HMAC audit key error: {}", err),
            AuditIntegrityError::SequenceMismatch {
                index,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Sequence violation at index {}: expected {}, found {}",
                    index, expected, found
                )
            }
            AuditIntegrityError::TimestampRegression {
                index,
                prev_timestamp,
                found_timestamp,
            } => {
                write!(
                    f,
                    "Timestamp regression at index {}: prev {}, found {}",
                    index, prev_timestamp, found_timestamp
                )
            }
            AuditIntegrityError::PrevHashMismatch {
                index,
                expected_prev_hash,
                found_prev_hash,
            } => {
                write!(
                    f,
                    "Cryptographic break at index {}: expected parent hash '{}', found '{}'",
                    index, expected_prev_hash, found_prev_hash
                )
            }
            AuditIntegrityError::HashVerificationFailed {
                index,
                stored_hash,
                computed_hash,
            } => {
                write!(
                    f,
                    "Tampering detected at index {}: stored hash '{}' != computed hash '{}'",
                    index, stored_hash, computed_hash
                )
            }
        }
    }
}

/// In-memory and persisted tamper-evident audit ledger
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLedger {
    pub records: Vec<AuditRecord>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }
}

/// Sanitizes audit target resources to strip userinfo, query parameters, and sensitive credentials
pub fn sanitize_audit_target(target: &str) -> String {
    let engine = crate::SecretGuardEngine::new();
    let scanned = engine.scan_and_sanitize(target).sanitized_text;

    if let Some(pos) = scanned.find("://") {
        let scheme = &scanned[..pos];
        let rest = &scanned[pos + 3..];
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let clean_auth = match authority.rfind('@') {
            Some(at) => &authority[at + 1..],
            None => authority,
        };
        let after_auth = &rest[auth_end..];
        let (path, has_query) = match after_auth.find('?') {
            Some(q) => (&after_auth[..q], true),
            None => match after_auth.find('#') {
                Some(h) => (&after_auth[..h], false),
                None => (after_auth, false),
            },
        };
        if has_query {
            format!("{}://{}{}[REDACTED_QUERY]", scheme, clean_auth, path)
        } else {
            format!("{}://{}{}", scheme, clean_auth, path)
        }
    } else {
        scanned
    }
}

impl AuditLedger {
    /// Appends a new verified authorization decision to the hash-chained ledger; fails closed if signing fails
    pub fn record_decision(
        &mut self,
        req: &OperationRequest,
        decision: &AuthorizationDecision,
    ) -> Result<&AuditRecord, std::io::Error> {
        let seq = (self.records.len() as u64) + 1;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let prev_hash = self
            .records
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());

        let decision_str = match decision {
            AuthorizationDecision::AllowDelegated => "AllowDelegated".to_string(),
            AuthorizationDecision::AllowRaw => "AllowRaw".to_string(),
            AuthorizationDecision::RequireHumanApproval { risk_level, .. } => {
                format!("RequireApproval:{}", risk_level)
            }
            AuthorizationDecision::Deny { reason } => format!("Deny:{}", reason),
        };

        // Redact any exposed secrets from target resource and decision strings before signing and persisting
        let engine = crate::SecretGuardEngine::new();
        let sanitized_target = sanitize_audit_target(&req.target_resource);
        let sanitized_decision = engine.scan_and_sanitize(&decision_str).sanitized_text;

        let hash = AuditRecord::compute_hash(
            seq,
            timestamp,
            req.requester.pid,
            &req.requester.executable_name,
            req.requester.requester_type,
            &req.credential_name,
            req.operation.as_str(),
            &sanitized_target,
            &sanitized_decision,
            &prev_hash,
        )?;

        let record = AuditRecord {
            sequence_number: seq,
            timestamp_epoch_secs: timestamp,
            requester_pid: req.requester.pid,
            requester_name: req.requester.executable_name.clone(),
            requester_type: req.requester.requester_type,
            credential_name: req.credential_name.clone(),
            operation: req.operation.as_str().to_string(),
            target_resource: sanitized_target,
            decision: sanitized_decision,
            prev_record_hash: prev_hash,
            record_hash: hash,
        };

        self.records.push(record);
        Ok(self.records.last().unwrap())
    }

    /// Cryptographically verifies the integrity of the entire audit chain
    pub fn verify_integrity(&self) -> Result<usize, AuditIntegrityError> {
        let key = get_or_create_audit_key().map_err(|e| {
            AuditIntegrityError::KeyError(format!("Failed to retrieve HMAC audit key: {}", e))
        })?;
        self.verify_integrity_with_key(&key)
    }

    /// Cryptographically verifies the integrity of the entire audit chain using a specific HMAC key
    pub fn verify_integrity_with_key(&self, key: &[u8]) -> Result<usize, AuditIntegrityError> {
        if self.records.is_empty() {
            return Err(AuditIntegrityError::EmptyLedger);
        }

        let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();

        for (idx, record) in self.records.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if record.sequence_number != expected_seq {
                return Err(AuditIntegrityError::SequenceMismatch {
                    index: idx,
                    expected: expected_seq,
                    found: record.sequence_number,
                });
            }

            if record.prev_record_hash != expected_prev_hash {
                return Err(AuditIntegrityError::PrevHashMismatch {
                    index: idx,
                    expected_prev_hash,
                    found_prev_hash: record.prev_record_hash.clone(),
                });
            }

            let computed = AuditRecord::compute_keyed_hash(
                key,
                record.sequence_number,
                record.timestamp_epoch_secs,
                record.requester_pid,
                &record.requester_name,
                record.requester_type,
                &record.credential_name,
                &record.operation,
                &record.target_resource,
                &record.decision,
                &record.prev_record_hash,
            );

            if computed != record.record_hash {
                return Err(AuditIntegrityError::HashVerificationFailed {
                    index: idx,
                    stored_hash: record.record_hash.clone(),
                    computed_hash: computed,
                });
            }

            expected_prev_hash = record.record_hash.clone();
        }

        Ok(self.records.len())
    }

    /// Resolves canonical audit ledger path (~/.secretguard/audit_ledger.json)
    pub fn get_default_path() -> PathBuf {
        let base = std::env::var("SECRETGUARD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                crate::vault::get_vault_dir().unwrap_or_else(|_| PathBuf::from(".secretguard"))
            });
        base.join("audit_ledger.json")
    }

    /// Persists audit ledger using atomic replacement with restricted permissions
    pub fn save(&self, custom_path: Option<&Path>) -> Result<(), std::io::Error> {
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _ = fs::create_dir_all(parent);

        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let pid = std::process::id();
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let tmp_filename = format!(".audit.{}.{:x}.tmp", pid, u64::from_le_bytes(nonce));
        let temp_path = parent.join(tmp_filename);

        use std::io::Write;
        let mut file = crate::vault::create_secure_file_exclusive(&temp_path, 0o600)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        let write_res = file.write_all(&data).and_then(|_| file.sync_all());
        if let Err(e) = write_res {
            drop(file);
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }
        drop(file);

        crate::vault::atomic_replace_file(&temp_path, &path).map_err(std::io::Error::other)?;
        Ok(())
    }

    /// Loads and cryptographically validates audit ledger from disk
    pub fn load(custom_path: Option<&Path>) -> Result<Self, String> {
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        if !path.exists() {
            return Ok(Self::new());
        }

        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to read audit metadata: {}", e))?;
        if meta.file_type().is_symlink() {
            return Err("Security Error: Audit ledger is an untrusted symlink!".to_string());
        }

        let mut attempts = 0;
        let data = loop {
            match fs::read(&path) {
                Ok(d) => break d,
                Err(e)
                    if attempts < 5
                        && (e.kind() == std::io::ErrorKind::PermissionDenied
                            || e.raw_os_error() == Some(32)) =>
                {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                Err(e) => return Err(format!("Failed to read audit ledger: {}", e)),
            }
        };
        let ledger: Self = serde_json::from_slice(&data)
            .map_err(|e| format!("Invalid audit JSON format: {}", e))?;

        if !ledger.records.is_empty() {
            ledger
                .verify_integrity()
                .map_err(|e| format!("Security Alert: Audit ledger verification failed: {}", e))?;
        }

        Ok(ledger)
    }

    /// CLI handler for `secretguard audit-ledger` / `secretguard ledger`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard audit-ledger - Tamper-Evident Cryptographic Security Audit Ledger
Inspect, tail, and cryptographically verify hash-chained security event logs.

USAGE:
    secretguard audit-ledger <SUBCOMMAND>

SUBCOMMANDS:
    verify               Cryptographically verify SHA-256 hash chaining of all logged events
    tail [N]             Display the last N security authorization decisions (default: 10)
    list                 Display all logged authorization records
    path                 Print the absolute filesystem location of the audit ledger
"#
            );
            return;
        }

        match args[0].as_str() {
            "verify" => match Self::load(None) {
                Ok(ledger) => {
                    if ledger.records.is_empty() {
                        println!("ℹ️  Audit Ledger Initialized: 0 records recorded so far (no events to verify).");
                    } else {
                        match ledger.verify_integrity() {
                            Ok(count) => {
                                println!(
                                    "\x1b[32m✅ Audit Ledger Integrity Verified: {} records intact\x1b[0m",
                                    count
                                );
                                println!("All SHA-256 links in the hash-chain match from genesis to head.");
                            }
                            Err(e) => {
                                eprintln!("\x1b[31m❌ AUDIT INTEGRITY BREACH: {}\x1b[0m", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("\x1b[31m❌ Failed to load audit ledger: {}\x1b[0m", e);
                    std::process::exit(1);
                }
            },
            "path" => {
                println!("{}", Self::get_default_path().display());
            }
            "tail" | "list" => {
                let limit = if args[0] == "tail" {
                    args.get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(10)
                } else {
                    usize::MAX
                };

                match Self::load(None) {
                    Ok(ledger) => {
                        println!("🛡️  SecretGuard Tamper-Evident Audit Ledger");
                        println!(
                            "──────────────────────────────────────────────────────────────────"
                        );
                        if ledger.records.is_empty() {
                            println!(
                                "Ledger is currently empty (0 authorization events recorded)."
                            );
                            return;
                        }

                        let start_idx = ledger.records.len().saturating_sub(limit);
                        for r in &ledger.records[start_idx..] {
                            println!(
                                "\x1b[1m#{:04}\x1b[0m [{}] \x1b[36m{:?}\x1b[0m ({})",
                                r.sequence_number, r.decision, r.requester_type, r.requester_name
                            );
                            println!("       Target:  {} ({})", r.target_resource, r.operation);
                            println!("       Cred:    {}", r.credential_name);
                            println!(
                                "       Hash:    \x1b[90m{}...\x1b[0m\n",
                                &r.record_hash[..16]
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read audit ledger: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!(
                    "Unknown audit-ledger subcommand '{}'. Run 'secretguard audit-ledger --help'.",
                    args[0]
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityContext;
    use crate::policy::OperationType;

    #[test]
    fn test_audit_hash_chain_verification() {
        let mut ledger = AuditLedger::new();
        let human = IdentityContext::mock(
            "bash",
            RequesterType::HumanInteractive,
            Some("org/repo"),
            None,
        );
        let req1 = OperationRequest::new(
            human.clone(),
            "TOKEN_A",
            OperationType::HttpGet,
            "https://api.github.com",
        );
        let req2 = OperationRequest::new(
            human,
            "TOKEN_B",
            OperationType::HttpPost,
            "https://api.github.com",
        );

        ledger
            .record_decision(&req1, &AuthorizationDecision::AllowRaw)
            .unwrap();
        ledger
            .record_decision(&req2, &AuthorizationDecision::AllowDelegated)
            .unwrap();

        assert_eq!(ledger.verify_integrity(), Ok(2));
    }

    #[test]
    fn test_audit_tampering_detected_loudly() {
        let mut ledger = AuditLedger::new();
        let agent = IdentityContext::mock(
            "claude",
            RequesterType::AutonomousAgent,
            Some("org/repo"),
            None,
        );
        let req = OperationRequest::new(
            agent,
            "GITHUB_TOKEN",
            OperationType::HttpDelete,
            "https://api.github.com",
        );

        ledger
            .record_decision(
                &req,
                &AuthorizationDecision::Deny {
                    reason: "Forbidden".to_string(),
                },
            )
            .unwrap();
        assert_eq!(ledger.verify_integrity(), Ok(1));

        // Maliciously tamper with decision string in memory
        ledger.records[0].decision = "AllowRaw".to_string();

        let verify_result = ledger.verify_integrity();
        assert!(matches!(
            verify_result,
            Err(AuditIntegrityError::HashVerificationFailed { .. })
        ));
    }
}
