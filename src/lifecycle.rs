//! Credential Lifecycle Management for SecretGuard
//!
//! Enforces an explicit, verified credential state machine:
//! - Active: Credential is valid, stored encrypted, and usable under policy.
//! - Quarantined: Compromised or leaked; immediately blocked from use locally.
//! - Revoked: Verified revoked upstream by provider API or confirmed invalidated.
//! - Expired: Time-to-live or max usage limit exceeded.
//! - PendingManualRotation: Provider requires human administrative dashboard rotation.
//!
//! NEVER reports successful rotation unless the upstream provider actually issued a replacement key.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Formal lifecycle state of a credential managed by SecretGuard
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialState {
    /// Credential is in good standing and authorized for policy-evaluated operations
    Active,
    /// Credential has been compromised or flagged; blocked by circuit-breaker
    Quarantined { quarantined_at: u64, reason: String },
    /// Credential confirmed permanently deactivated upstream by provider API
    Revoked {
        revoked_at: u64,
        verification_method: String,
    },
    /// Credential lease or validity window has elapsed
    Expired { expired_at: u64 },
    /// Upstream provider does not support automated rotation; manual dashboard rotation required
    PendingManualRotation {
        flagged_at: u64,
        provider_name: String,
        rotation_url: String,
        instructions: String,
    },
}

/// Metadata and lifecycle record for a stored credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub name: String,
    pub provider: String,
    pub fingerprint: String,
    pub state: CredentialState,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub usage_count: u64,
}

impl CredentialRecord {
    pub fn new(name: &str, provider: &str, fingerprint: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            name: name.to_string(),
            provider: provider.to_string(),
            fingerprint: fingerprint.to_string(),
            state: CredentialState::Active,
            created_at: now,
            last_used_at: None,
            usage_count: 0,
        }
    }

    /// Masks a sensitive token into a safe audit fingerprint (e.g. "ghp_...7a9f")
    pub fn compute_fingerprint(token: &str) -> String {
        let chars: Vec<char> = token.chars().collect();
        if chars.len() > 8 {
            let prefix: String = chars[..4].iter().collect();
            let suffix: String = chars[chars.len() - 4..].iter().collect();
            format!("{}...{}", prefix, suffix)
        } else {
            "***".to_string()
        }
    }

    /// Moves credential into Quarantined state
    pub fn quarantine(&mut self, reason: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.state = CredentialState::Quarantined {
            quarantined_at: now,
            reason: reason.to_string(),
        };
    }

    /// Marks credential as requiring manual rotation by a human administrator
    pub fn require_manual_rotation(&mut self, rotation_url: &str, instructions: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.state = CredentialState::PendingManualRotation {
            flagged_at: now,
            provider_name: self.provider.clone(),
            rotation_url: rotation_url.to_string(),
            instructions: instructions.to_string(),
        };
    }

    /// Marks credential as confirmed revoked upstream
    pub fn mark_revoked(&mut self, verification_method: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.state = CredentialState::Revoked {
            revoked_at: now,
            verification_method: verification_method.to_string(),
        };
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.state, CredentialState::Active)
    }
}

/// In-memory and persisted credential lifecycle tracker
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LifecycleManager {
    pub credentials: HashMap<String, CredentialRecord>,
}

impl LifecycleManager {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    pub fn find_by_name(&self, name: &str) -> Option<&CredentialRecord> {
        self.credentials
            .values()
            .find(|r| r.name.eq_ignore_ascii_case(name) || r.provider.eq_ignore_ascii_case(name))
    }

    pub fn register(&mut self, name: &str, provider: &str, raw_token: &str) {
        let fingerprint = CredentialRecord::compute_fingerprint(raw_token);
        let record = CredentialRecord::new(name, provider, &fingerprint);
        self.credentials.insert(name.to_string(), record);
    }

    pub fn quarantine_credential(&mut self, name: &str, reason: &str) -> Option<&CredentialRecord> {
        if let Some(record) = self.credentials.get_mut(name) {
            record.quarantine(reason);
            Some(record)
        } else {
            None
        }
    }

    pub fn quarantine_by_name_or_token(
        &mut self,
        identifier: &str,
        raw_token: &str,
        reason: &str,
    ) -> &CredentialRecord {
        let fp = CredentialRecord::compute_fingerprint(raw_token);
        let target_key = self
            .credentials
            .iter()
            .find(|(k, v)| k.as_str() == identifier || v.fingerprint == fp)
            .map(|(k, _)| k.clone());

        let key = if let Some(k) = target_key {
            k
        } else {
            let record = CredentialRecord::new(identifier, identifier, &fp);
            self.credentials.insert(identifier.to_string(), record);
            identifier.to_string()
        };

        let rec = self.credentials.get_mut(&key).unwrap();
        rec.quarantine(reason);
        rec
    }

    pub fn get_default_path() -> PathBuf {
        let base = std::env::var("SECRETGUARD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                crate::vault::get_vault_dir().unwrap_or_else(|_| PathBuf::from(".secretguard"))
            });
        let base = crate::vault::resolve_canonical_security_path(&base).unwrap_or(base);
        base.join("lifecycle.json")
    }

    pub fn load(custom_path: Option<&Path>) -> Result<Self, std::io::Error> {
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let path = crate::vault::resolve_canonical_security_path(&path).unwrap_or(path);
        if let Some(mut file) = crate::vault::open_secure_file_for_read(&path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?
        {
            use std::io::Read;
            let mut data = String::new();
            file.read_to_string(&mut data)?;
            if data.trim().is_empty() {
                return Ok(Self::new());
            }
            serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        } else {
            Ok(Self::new())
        }
    }

    pub fn save(&self, custom_path: Option<&Path>) -> Result<(), std::io::Error> {
        let path = custom_path
            .map(PathBuf::from)
            .unwrap_or_else(Self::get_default_path);
        let path = crate::vault::resolve_canonical_security_path(&path).unwrap_or(path);
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let _ = fs::create_dir_all(parent);

        let data = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;

        let tmp_path = parent.join(format!(".tmp_lifecycle_{}", std::process::id()));
        fs::write(&tmp_path, data.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        crate::vault::atomic_replace_file(&tmp_path, &path).map_err(std::io::Error::other)
    }

    pub fn record_usage(&mut self, name: &str) -> bool {
        if let Some(record) = self.credentials.get_mut(name) {
            if record.is_usable() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                record.last_used_at = Some(now);
                record.usage_count += 1;
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_quarantine_blocks_usage() {
        let mut lm = LifecycleManager::new();
        lm.register(
            "GITHUB_TOKEN",
            "GitHub Personal Access Token",
            "ghp_test1234567890abcdef",
        );

        assert!(lm.record_usage("GITHUB_TOKEN"));

        // Quarantine credential
        lm.quarantine_credential("GITHUB_TOKEN", "Exposed in terminal stdout");

        let rec = lm.credentials.get("GITHUB_TOKEN").unwrap();
        assert!(!rec.is_usable());
        assert!(!lm.record_usage("GITHUB_TOKEN"));
    }

    #[test]
    fn test_manual_rotation_instructions_retained() {
        let mut rec = CredentialRecord::new(
            "OPENAI_KEY",
            "OpenAI API",
            &CredentialRecord::compute_fingerprint("sk-proj-testkey12345678"),
        );

        rec.require_manual_rotation(
            "https://platform.openai.com/api-keys",
            "Generate new key in OpenAI dashboard and replace via 'secretguard vault set OPENAI_KEY'",
        );

        match rec.state {
            CredentialState::PendingManualRotation {
                rotation_url,
                instructions,
                ..
            } => {
                assert!(rotation_url.contains("openai.com"));
                assert!(instructions.contains("secretguard vault set"));
            }
            other => panic!("Expected PendingManualRotation, got {:?}", other),
        }
    }
}
