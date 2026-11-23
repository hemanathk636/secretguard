//! Tamper-Evident Security Audit Ledger for SecretGuard
//! Cryptographically hash-chained, monotonically ordered, append-only security logs.

use crate::identity::RequesterType;
use crate::policy::{AuthorizationDecision, OperationRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
    /// Computes deterministic SHA-256 hash across record attributes
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
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seq.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(format!("{:?}", req_type).as_bytes());
        hasher.update(cred.as_bytes());
        hasher.update(op.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(decision.as_bytes());
        hasher.update(prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Verification failure detail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditIntegrityError {
    EmptyLedger,
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

    /// Appends a new verified authorization decision to the hash-chained ledger
    pub fn record_decision(
        &mut self,
        req: &OperationRequest,
        decision: &AuthorizationDecision,
    ) -> &AuditRecord {
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

        let hash = AuditRecord::compute_hash(
            seq,
            timestamp,
            req.requester.pid,
            &req.requester.executable_name,
            req.requester.requester_type,
            &req.credential_name,
            req.operation.as_str(),
            &req.target_resource,
            &decision_str,
            &prev_hash,
        );

        let record = AuditRecord {
            sequence_number: seq,
            timestamp_epoch_secs: timestamp,
            requester_pid: req.requester.pid,
            requester_name: req.requester.executable_name.clone(),
            requester_type: req.requester.requester_type,
            credential_name: req.credential_name.clone(),
            operation: req.operation.as_str().to_string(),
            target_resource: req.target_resource.clone(),
            decision: decision_str,
            prev_record_hash: prev_hash,
            record_hash: hash,
        };

        self.records.push(record);
        self.records.last().unwrap()
    }

    /// Cryptographically verifies the integrity of the entire audit chain
    pub fn verify_integrity(&self) -> Result<usize, AuditIntegrityError> {
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

            let computed = AuditRecord::compute_hash(
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
                #[cfg(windows)]
                {
                    std::env::var("USERPROFILE")
                        .map(|p| PathBuf::from(p).join(".secretguard"))
                        .unwrap_or_else(|_| PathBuf::from(".secretguard"))
                }
                #[cfg(not(windows))]
                {
                    std::env::var("HOME")
                        .map(|p| PathBuf::from(p).join(".secretguard"))
                        .unwrap_or_else(|_| PathBuf::from(".secretguard"))
                }
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

        let data = fs::read(&path).map_err(|e| format!("Failed to read audit ledger: {}", e))?;
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

        ledger.record_decision(&req1, &AuthorizationDecision::AllowRaw);
        ledger.record_decision(&req2, &AuthorizationDecision::AllowDelegated);

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

        ledger.record_decision(
            &req,
            &AuthorizationDecision::Deny {
                reason: "Forbidden".to_string(),
            },
        );
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
