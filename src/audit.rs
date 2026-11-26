//! Tamper-Evident Security Audit Ledger for SecretGuard
//! Cryptographically hash-chained, monotonically ordered, append-only security logs.
//!
//! Security Model Note:
//! The keyed HMAC-SHA256 hash chain provides *tamper detection* for record modification,
//! deletion, reordering, and truncation. It does not prevent tampering by a local attacker
//! who already has read/write access to both `audit_ledger.json` and `audit.hmac.key`.

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

#[cfg(test)]
static TEST_AUDIT_KEY: std::sync::RwLock<Option<[u8; 32]>> = std::sync::RwLock::new(None);

/// Returns or initializes local HMAC signing key for tamper-proof audit verification
pub fn get_or_create_audit_key() -> Result<[u8; 32], std::io::Error> {
    #[cfg(test)]
    if let Ok(guard) = TEST_AUDIT_KEY.read() {
        if let Some(k) = *guard {
            return Ok(k);
        }
    }

    let dir = std::env::var("SECRETGUARD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            crate::vault::get_vault_dir().unwrap_or_else(|_| PathBuf::from(".secretguard"))
        });
    fs::create_dir_all(&dir)?;
    let dir = crate::vault::resolve_canonical_security_path(&dir).unwrap_or(dir);
    let key_path = dir.join("audit.hmac.key");

    if let Some(mut file) = crate::vault::open_secure_file_for_read(&key_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?
    {
        use std::io::Read;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        if data.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&data);
            crate::vault::volatile_zeroize(&mut data);
            return Ok(k);
        } else {
            let len = data.len();
            crate::vault::volatile_zeroize(&mut data);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Security Alert: Corrupt audit.hmac.key file: expected 32 bytes, found {}",
                    len
                ),
            ));
        }
    }

    if let Ok(guard_val) = std::fs::metadata(dir.join("audit_ledger.json")) {
        if guard_val.len() > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Security Alert: audit.hmac.key is missing while audit_ledger.json already exists. Refusing to regenerate a new key.",
            ));
        }
    }

    // Fail-Closed: Generate 32-byte CSPRNG key and persist exclusively with 0o600.
    // If creation or writing fails, fail closed with Err - never return an ephemeral in-memory key!
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    match crate::vault::create_secure_file_exclusive(&key_path, 0o600) {
        Ok(mut file) => {
            file.write_all(&k)?;
            file.sync_all()?;
            Ok(k)
        }
        Err(_) => {
            // Handle concurrent creation by another thread/process
            if let Some(mut file) = crate::vault::open_secure_file_for_read(&key_path)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?
            {
                use std::io::Read;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                if data.len() == 32 {
                    let mut existing = [0u8; 32];
                    existing.copy_from_slice(&data);
                    crate::vault::volatile_zeroize(&mut data);
                    return Ok(existing);
                }
                crate::vault::volatile_zeroize(&mut data);
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Failed to create or read audit.hmac.key",
            ))
        }
    }
}

#[cfg(test)]
pub fn set_test_audit_key(key: [u8; 32]) {
    let mut guard = TEST_AUDIT_KEY.write().unwrap();
    *guard = Some(key);
}

#[cfg(test)]
pub fn clear_test_audit_key() {
    let mut guard = TEST_AUDIT_KEY.write().unwrap();
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
        let mut key = get_or_create_audit_key()?;
        let hash = Self::compute_keyed_hash(
            &key, seq, timestamp, pid, name, req_type, cred, op, target, decision, prev_hash,
        );
        crate::vault::volatile_zeroize(&mut key);
        Ok(hash)
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
    TruncationDetected {
        expected_seq: u64,
        found_seq: u64,
        reason: String,
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
            AuditIntegrityError::TruncationDetected {
                expected_seq,
                found_seq,
                reason,
            } => {
                write!(
                    f,
                    "Audit truncation/rollback detected (expected seq >= {}, found {}): {}",
                    expected_seq, found_seq, reason
                )
            }
        }
    }
}

/// HMAC-authenticated head checkpoint to detect tail truncation and rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub last_seq: u64,
    pub head_hash: String,
    pub checkpoint_mac: String,
}

impl AuditCheckpoint {
    pub fn path_for(ledger_path: &Path) -> PathBuf {
        if ledger_path.file_name() == Some(std::ffi::OsStr::new("audit_ledger.json")) {
            ledger_path.with_file_name("audit_checkpoint.json")
        } else {
            ledger_path.with_extension("checkpoint.json")
        }
    }

    pub fn compute_mac(key: &[u8], last_seq: u64, head_hash: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"secretguard-audit-checkpoint-v1|");
        mac.update(last_seq.to_string().as_bytes());
        mac.update(b"|");
        mac.update(head_hash.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub fn verify_mac(&self, key: &[u8]) -> Result<(), AuditIntegrityError> {
        if self.checkpoint_mac.len() != 64 {
            return Err(AuditIntegrityError::TruncationDetected {
                expected_seq: self.last_seq,
                found_seq: 0,
                reason: "Corrupt audit checkpoint MAC length".to_string(),
            });
        }
        let sig_bytes: Vec<u8> = (0..self.checkpoint_mac.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.checkpoint_mac[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| AuditIntegrityError::TruncationDetected {
                expected_seq: self.last_seq,
                found_seq: 0,
                reason: "Corrupt audit checkpoint MAC hex".to_string(),
            })?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"secretguard-audit-checkpoint-v1|");
        mac.update(self.last_seq.to_string().as_bytes());
        mac.update(b"|");
        mac.update(self.head_hash.as_bytes());
        mac.verify_slice(&sig_bytes)
            .map_err(|_| AuditIntegrityError::TruncationDetected {
                expected_seq: self.last_seq,
                found_seq: 0,
                reason: "Audit checkpoint MAC verification failed".to_string(),
            })
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

static INPROC_AUDIT_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn lock_inproc_audit() -> std::sync::MutexGuard<'static, ()> {
    INPROC_AUDIT_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Persistent OS-kernel-managed lock on `.audit_ledger.lock`.
/// Uses `LockFileEx`/`UnlockFileEx` on Windows and `flock` (`LOCK_EX`/`LOCK_SH`/`LOCK_UN`) on Unix.
/// Never deleted or replaced during normal operation; automatically released by the OS kernel on process exit.
pub struct AuditKernelLock {
    file: fs::File,
}

impl AuditKernelLock {
    fn open_lock_file(parent: &Path) -> Result<fs::File, String> {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create audit directory: {}", e))?;
        let mut val_attempts = 0;
        loop {
            match crate::vault::validate_secure_path(parent, false) {
                Ok(()) => break,
                Err(e) if val_attempts < 5 && e.contains("Win32 error: 32") => {
                    val_attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
        let lock_path = parent.join(".audit_ledger.lock");
        if let Ok(meta) = fs::symlink_metadata(&lock_path) {
            if meta.file_type().is_symlink() {
                return Err(
                    "Security Error: Audit lockfile is a symlink/reparse point.".to_string()
                );
            }
        } else {
            let _ = crate::vault::create_secure_file_exclusive(&lock_path, 0o600);
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut open_attempts = 0;
            loop {
                match fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(3) // FILE_SHARE_READ | FILE_SHARE_WRITE (disallow delete/replace)
                    .open(&lock_path)
                {
                    Ok(f) => return Ok(f),
                    Err(e) if open_attempts < 5 && e.raw_os_error() == Some(32) => {
                        open_attempts += 1;
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => {
                        return Err(format!("Failed to open persistent audit lockfile: {}", e))
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|e| format!("Failed to open persistent audit lockfile: {}", e))
        }
    }

    #[cfg(windows)]
    fn win_try_lock(file: &fs::File, exclusive: bool) -> Result<bool, String> {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            h_event: isize,
        }
        extern "system" {
            fn LockFileEx(
                h_file: isize,
                dw_flags: u32,
                dw_reserved: u32,
                n_number_of_bytes_to_lock_low: u32,
                n_number_of_bytes_to_lock_high: u32,
                lp_overlapped: *mut Overlapped,
            ) -> i32;
            fn GetLastError() -> u32;
        }
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        const ERROR_LOCK_VIOLATION: u32 = 33;
        const ERROR_IO_PENDING: u32 = 997;

        let flags = if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
        } else {
            LOCKFILE_FAIL_IMMEDIATELY
        };
        let mut ov = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        let ok = unsafe { LockFileEx(file.as_raw_handle() as isize, flags, 0, 1, 0, &mut ov) };
        if ok != 0 {
            return Ok(true);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_LOCK_VIOLATION || err == ERROR_IO_PENDING {
            return Ok(false);
        }
        Err(format!(
            "Security Fail-Closed: OS audit locking failed (Win32 error {})",
            err
        ))
    }

    fn try_acquire_mode(parent: &Path, exclusive: bool) -> Result<Option<Self>, String> {
        let file = Self::open_lock_file(parent)?;
        #[cfg(windows)]
        {
            if Self::win_try_lock(&file, exclusive)? {
                return Ok(Some(Self { file }));
            }
            Ok(None)
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let op = if exclusive {
                libc::LOCK_EX | libc::LOCK_NB
            } else {
                libc::LOCK_SH | libc::LOCK_NB
            };
            let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
            if rc == 0 {
                return Ok(Some(Self { file }));
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            Err(format!(
                "Security Fail-Closed: OS audit locking failed ({})",
                err
            ))
        }
        #[cfg(not(any(windows, unix)))]
        {
            let _ = exclusive;
            Err(
                "Security Fail-Closed: OS kernel file locking is unsupported on this platform."
                    .to_string(),
            )
        }
    }

    pub fn try_acquire_exclusive(parent: &Path) -> Result<Option<Self>, String> {
        Self::try_acquire_mode(parent, true)
    }

    pub fn try_acquire_shared(parent: &Path) -> Result<Option<Self>, String> {
        Self::try_acquire_mode(parent, false)
    }

    pub fn acquire_exclusive(parent: &Path) -> Result<Self, String> {
        for _ in 0..200 {
            if let Some(guard) = Self::try_acquire_exclusive(parent)? {
                // Best-effort diagnostic owner metadata kept separately from the kernel lock
                let diag_path = parent.join(".audit_ledger.owner");
                if !fs::symlink_metadata(&diag_path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    let _ = fs::write(&diag_path, format!("pid={}\n", std::process::id()));
                }
                return Ok(guard);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Err("Timed out acquiring OS audit ledger exclusive lock.".to_string())
    }

    pub fn acquire_shared(parent: &Path) -> Result<Self, String> {
        for _ in 0..200 {
            if let Some(guard) = Self::try_acquire_shared(parent)? {
                return Ok(guard);
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Err("Timed out acquiring OS audit ledger shared lock.".to_string())
    }
}

impl Drop for AuditKernelLock {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            #[repr(C)]
            struct Overlapped {
                internal: usize,
                internal_high: usize,
                offset: u32,
                offset_high: u32,
                h_event: isize,
            }
            extern "system" {
                fn UnlockFileEx(
                    h_file: isize,
                    dw_reserved: u32,
                    n_number_of_bytes_to_unlock_low: u32,
                    n_number_of_bytes_to_unlock_high: u32,
                    lp_overlapped: *mut Overlapped,
                ) -> i32;
            }
            let mut ov = Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                h_event: 0,
            };
            unsafe {
                UnlockFileEx(self.file.as_raw_handle() as isize, 0, 1, 0, &mut ov);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
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

        // Redact any exposed secrets from credential name, target resource, and decision strings before signing and persisting
        let engine = crate::SecretGuardEngine::new();
        let sanitized_cred = engine
            .scan_and_sanitize(&req.credential_name)
            .sanitized_text;
        let sanitized_target = sanitize_audit_target(&req.target_resource);
        let sanitized_decision = engine.scan_and_sanitize(&decision_str).sanitized_text;

        let hash = AuditRecord::compute_hash(
            seq,
            timestamp,
            req.requester.pid,
            &req.requester.executable_name,
            req.requester.requester_type,
            &sanitized_cred,
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
            credential_name: sanitized_cred,
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
        let mut key = get_or_create_audit_key().map_err(|e| {
            AuditIntegrityError::KeyError(format!("Failed to retrieve HMAC audit key: {}", e))
        })?;
        let res = self.verify_integrity_with_key(&key);
        crate::vault::volatile_zeroize(&mut key);
        res
    }

    /// Cryptographically verifies the integrity of the entire audit chain using a specific HMAC key
    pub fn verify_integrity_with_key(&self, key: &[u8]) -> Result<usize, AuditIntegrityError> {
        if self.records.is_empty() {
            return Err(AuditIntegrityError::EmptyLedger);
        }

        let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
        let mut prev_timestamp = 0u64;

        for (idx, record) in self.records.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if record.sequence_number != expected_seq {
                return Err(AuditIntegrityError::SequenceMismatch {
                    index: idx,
                    expected: expected_seq,
                    found: record.sequence_number,
                });
            }

            if record.timestamp_epoch_secs < prev_timestamp {
                return Err(AuditIntegrityError::TimestampRegression {
                    index: idx,
                    prev_timestamp,
                    found_timestamp: record.timestamp_epoch_secs,
                });
            }
            prev_timestamp = record.timestamp_epoch_secs;

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
        let base = crate::vault::resolve_canonical_security_path(&base).unwrap_or(base);
        base.join("audit_ledger.json")
    }

    fn save_locked(&self, path: &Path) -> Result<(), std::io::Error> {
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

        crate::vault::atomic_replace_file(&temp_path, path).map_err(std::io::Error::other)?;
        Self::write_checkpoint_for_path(self, path).map_err(std::io::Error::other)?;
        Ok(())
    }

    /// Persists audit ledger using atomic replacement with restricted permissions under OS kernel lock
    pub fn save(&self, custom_path: Option<&Path>) -> Result<(), std::io::Error> {
        let _inproc = lock_inproc_audit();
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let path = crate::vault::resolve_canonical_security_path(&path).unwrap_or(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _kernel_lock =
            AuditKernelLock::acquire_exclusive(parent).map_err(std::io::Error::other)?;
        self.save_locked(&path)
    }

    /// Appends a single decision atomically under an in-process + persistent OS kernel lock,
    /// verifying existing ledger integrity before appending and persisting.
    pub fn append_decision_atomic(
        req: &OperationRequest,
        decision: &AuthorizationDecision,
        custom_path: Option<&Path>,
    ) -> Result<AuditRecord, String> {
        let _inproc = lock_inproc_audit();

        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let path = crate::vault::resolve_canonical_security_path(&path).unwrap_or(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _kernel_lock = AuditKernelLock::acquire_exclusive(parent)?;

        let mut ledger = Self::load_locked(&path)?;
        let rec = ledger
            .record_decision(req, decision)
            .map_err(|e| e.to_string())?
            .clone();
        ledger.save_locked(&path).map_err(|e| e.to_string())?;
        Ok(rec)
    }

    fn write_checkpoint_for_path(ledger: &Self, ledger_path: &Path) -> Result<(), String> {
        let Some(last) = ledger.records.last() else {
            return Ok(());
        };
        let mut key = get_or_create_audit_key()
            .map_err(|e| format!("Failed to get audit key for checkpoint: {}", e))?;
        let mac = AuditCheckpoint::compute_mac(&key, last.sequence_number, &last.record_hash);
        crate::vault::volatile_zeroize(&mut key);

        let cp = AuditCheckpoint {
            last_seq: last.sequence_number,
            head_hash: last.record_hash.clone(),
            checkpoint_mac: mac,
        };
        let cp_path = AuditCheckpoint::path_for(ledger_path);
        let parent = cp_path.parent().unwrap_or_else(|| Path::new("."));
        let mut nonce = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let tmp_path = parent.join(format!(
            ".audit_cp.{}.{:x}.tmp",
            std::process::id(),
            u64::from_le_bytes(nonce)
        ));
        let data = serde_json::to_vec_pretty(&cp)
            .map_err(|e| format!("Failed to serialize audit checkpoint: {}", e))?;
        {
            use std::io::Write;
            let mut file = crate::vault::create_secure_file_exclusive(&tmp_path, 0o600)
                .map_err(|e| format!("Failed to create temp audit checkpoint: {}", e))?;
            if let Err(e) = file.write_all(&data).and_then(|_| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("Failed to write audit checkpoint: {}", e));
            }
        }
        crate::vault::atomic_replace_file(&tmp_path, &cp_path)
            .map_err(|e| format!("Failed to persist audit checkpoint: {}", e))?;
        Ok(())
    }

    pub fn verify_checkpoint_at(
        ledger: &Self,
        ledger_path: &Path,
    ) -> Result<(), AuditIntegrityError> {
        let cp_path = AuditCheckpoint::path_for(ledger_path);
        let file_opt = crate::vault::open_secure_file_for_read(&cp_path)
            .map_err(AuditIntegrityError::KeyError)?;
        let Some(mut file) = file_opt else {
            if let Some(last) = ledger.records.last() {
                return Err(AuditIntegrityError::TruncationDetected {
                    expected_seq: last.sequence_number,
                    found_seq: 0,
                    reason: "Audit checkpoint file is missing for non-empty ledger".to_string(),
                });
            }
            return Ok(());
        };
        use std::io::Read;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| {
            AuditIntegrityError::KeyError(format!("Failed to read checkpoint: {}", e))
        })?;
        let cp: AuditCheckpoint =
            serde_json::from_slice(&data).map_err(|e| AuditIntegrityError::TruncationDetected {
                expected_seq: 0,
                found_seq: ledger
                    .records
                    .last()
                    .map(|r| r.sequence_number)
                    .unwrap_or(0),
                reason: format!("Corrupt audit checkpoint JSON: {}", e),
            })?;
        let mut key =
            get_or_create_audit_key().map_err(|e| AuditIntegrityError::KeyError(e.to_string()))?;
        let verify_res = cp.verify_mac(&key);
        crate::vault::volatile_zeroize(&mut key);
        verify_res?;

        match ledger.records.last() {
            None => {
                if cp.last_seq > 0 {
                    return Err(AuditIntegrityError::TruncationDetected {
                        expected_seq: cp.last_seq,
                        found_seq: 0,
                        reason: "Ledger is empty but checkpoint records prior entries".to_string(),
                    });
                }
            }
            Some(last) => {
                if last.sequence_number < cp.last_seq {
                    return Err(AuditIntegrityError::TruncationDetected {
                        expected_seq: cp.last_seq,
                        found_seq: last.sequence_number,
                        reason: "Tail truncation or rollback detected against checkpoint"
                            .to_string(),
                    });
                }
                if last.sequence_number == cp.last_seq && last.record_hash != cp.head_hash {
                    return Err(AuditIntegrityError::TruncationDetected {
                        expected_seq: cp.last_seq,
                        found_seq: last.sequence_number,
                        reason: "Ledger head hash does not match checkpoint".to_string(),
                    });
                }
                if last.sequence_number > cp.last_seq {
                    let cp_idx = cp.last_seq.checked_sub(1).map(|i| i as usize);
                    let matches_ancestor = cp_idx
                        .and_then(|idx| ledger.records.get(idx))
                        .map(|r| r.sequence_number == cp.last_seq && r.record_hash == cp.head_hash)
                        .unwrap_or(false);
                    if !matches_ancestor {
                        return Err(AuditIntegrityError::TruncationDetected {
                            expected_seq: cp.last_seq,
                            found_seq: last.sequence_number,
                            reason: "Ledger history diverges from audit checkpoint".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn load_locked(path: &Path) -> Result<Self, String> {
        use std::io::Read;
        let mut attempts = 0;
        let file_opt = loop {
            match crate::vault::open_secure_file_for_read(path) {
                Ok(f) => break f,
                Err(e)
                    if attempts < 5
                        && (e.contains("Permission denied")
                            || e.contains("Win32 error: 32")
                            || e.contains("os error 13")) =>
                {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(format!("Failed to read audit ledger: {}", e)),
            }
        };

        let mut file = match file_opt {
            Some(f) => f,
            None => {
                let empty = Self::new();
                Self::verify_checkpoint_at(&empty, path).map_err(|e| {
                    format!("Security Alert: Audit ledger verification failed: {}", e)
                })?;
                return Ok(empty);
            }
        };

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| format!("Failed to read audit ledger: {}", e))?;

        if data.is_empty() {
            let empty = Self::new();
            Self::verify_checkpoint_at(&empty, path)
                .map_err(|e| format!("Security Alert: Audit ledger verification failed: {}", e))?;
            return Ok(empty);
        }

        let ledger: Self = serde_json::from_slice(&data)
            .map_err(|e| format!("Invalid audit JSON format: {}", e))?;

        if !ledger.records.is_empty() {
            ledger
                .verify_integrity()
                .map_err(|e| format!("Security Alert: Audit ledger verification failed: {}", e))?;
        }
        Self::verify_checkpoint_at(&ledger, path)
            .map_err(|e| format!("Security Alert: Audit ledger verification failed: {}", e))?;

        Ok(ledger)
    }

    /// Loads and cryptographically validates audit ledger from disk under OS shared lock
    pub fn load(custom_path: Option<&Path>) -> Result<Self, String> {
        let _inproc = lock_inproc_audit();
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let path = crate::vault::resolve_canonical_security_path(&path).unwrap_or(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _kernel_lock = AuditKernelLock::acquire_shared(parent)?;
        Self::load_locked(&path)
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
                        println!("â„¹ï¸  Audit Ledger Initialized: 0 records recorded so far (no events to verify).");
                    } else {
                        match ledger.verify_integrity() {
                            Ok(count) => {
                                println!(
                                    "\x1b[32mâœ… Audit Ledger Integrity Verified: {} records intact\x1b[0m",
                                    count
                                );
                                println!("All SHA-256 links in the hash-chain match from genesis to head.");
                            }
                            Err(e) => {
                                eprintln!("\x1b[31mâŒ AUDIT INTEGRITY BREACH: {}\x1b[0m", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("\x1b[31mâŒ Failed to load audit ledger: {}\x1b[0m", e);
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
                        println!("ðŸ›¡ï¸  SecretGuard Tamper-Evident Audit Ledger");
                        println!(
                            "â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€"
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
        let _lock = crate::vault::TERMINAL_INPUT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let _lock = crate::vault::TERMINAL_INPUT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
