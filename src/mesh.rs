use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshMember {
    pub name: String,
    pub salt_b64: Option<String>,
    pub public_key_fingerprint: String,
    /// Encrypted copy of the project master key (AES-256) encrypted with Argon2id(member_passphrase, salt)
    pub encrypted_master_key_b64: String,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeshVaultStore {
    pub version: u32,
    pub project_name: String,
    pub created_at: u64,
    pub members: HashMap<String, MeshMember>,
    /// The actual project secrets encrypted with the 256-bit project master key
    pub encrypted_payload_b64: String,
    pub payload_nonce_b64: String,
}

pub struct MeshManager;

impl MeshManager {
    /// Get path to `.secretguard/mesh.vault` in the active repository or directory
    pub fn get_mesh_vault_path(repo_path: Option<&Path>) -> PathBuf {
        let base = repo_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(".secretguard").join("mesh.vault")
    }

    /// Helper: Derive 32-byte key from password using Argon2id with random stored salt
    fn derive_key(identity_or_password: &str, salt: Option<&[u8]>) -> [u8; 32] {
        if let Some(salt_bytes) = salt {
            use argon2::Argon2;
            let mut out = [0u8; 32];
            if Argon2::default()
                .hash_password_into(identity_or_password.as_bytes(), salt_bytes, &mut out)
                .is_ok()
            {
                return out;
            }
        }
        // Fallback for legacy vaults
        let mut hasher = Sha256::new();
        hasher.update(identity_or_password.as_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Atomically writes the mesh vault file with restricted permissions (0600 on Unix)
    fn save_mesh_vault(vault_path: &Path, json: &str) -> Result<(), String> {
        let tmp_path = vault_path.with_extension(format!("tmp.{}", std::process::id()));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| format!("Failed to create temporary mesh vault: {}", e))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("Failed to write mesh vault: {}", e))?;
            f.sync_all()
                .map_err(|e| format!("Failed to sync mesh vault: {}", e))?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp_path, json.as_bytes())
                .map_err(|e| format!("Failed to write mesh vault: {}", e))?;
        }
        fs::rename(&tmp_path, vault_path)
            .map_err(|e| format!("Failed to atomically replace mesh vault: {}", e))?;
        Ok(())
    }

    /// Initialize a new Zero-Knowledge Mesh Vault with the creator as the first member
    pub fn init_mesh(
        creator_name: &str,
        creator_passphrase: &str,
        project_name: &str,
        repo_path: Option<&Path>,
    ) -> Result<PathBuf, String> {
        let vault_path = Self::get_mesh_vault_path(repo_path);
        if let Some(parent) = vault_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create .secretguard dir: {}", e))?;
        }

        // 1. Generate an authentic 256-bit cryptographically secure random Project Master Key
        let mut master_key = [0u8; 32];
        OsRng.fill_bytes(&mut master_key);

        // 2. Encrypt the master key for the creator using Argon2id with random 16-byte salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let creator_key_bytes = Self::derive_key(creator_passphrase, Some(&salt));
        let creator_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&creator_key_bytes));

        let mut creator_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut creator_nonce);
        let enc_master_key = creator_cipher
            .encrypt(Nonce::from_slice(&creator_nonce), master_key.as_ref())
            .map_err(|e| format!("Failed to encrypt master key: {}", e))?;

        // 3. Create initial empty payload (empty JSON map of secrets) encrypted with master_key
        let empty_secrets = "{}";
        let master_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
        let mut payload_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut payload_nonce);
        let enc_payload = master_cipher
            .encrypt(Nonce::from_slice(&payload_nonce), empty_secrets.as_bytes())
            .map_err(|e| format!("Failed to encrypt payload: {}", e))?;

        let mut hasher = Sha256::new();
        hasher.update(creator_passphrase.as_bytes());
        let fp = format!("{:x}", hasher.finalize())[..12].to_string();

        let member = MeshMember {
            name: creator_name.to_string(),
            salt_b64: Some(Self::encode_b64(&salt)),
            public_key_fingerprint: fp,
            encrypted_master_key_b64: Self::encode_b64(&enc_master_key),
            nonce_b64: Self::encode_b64(&creator_nonce),
        };

        let mut members = HashMap::new();
        members.insert(creator_name.to_string(), member);

        let store = MeshVaultStore {
            version: 1,
            project_name: project_name.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            members,
            encrypted_payload_b64: Self::encode_b64(&enc_payload),
            payload_nonce_b64: Self::encode_b64(&payload_nonce),
        };

        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| format!("Serialization error: {}", e))?;
        Self::save_mesh_vault(&vault_path, &json)?;

        Ok(vault_path)
    }

    /// Read the mesh store from disk
    pub fn read_store(repo_path: Option<&Path>) -> Result<MeshVaultStore, String> {
        let vault_path = Self::get_mesh_vault_path(repo_path);
        if !vault_path.exists() {
            return Err("No Mesh Vault found. Run 'secretguard mesh init' first.".to_string());
        }
        let data =
            fs::read_to_string(&vault_path).map_err(|e| format!("Failed to read vault: {}", e))?;
        serde_json::from_str(&data).map_err(|e| format!("Invalid vault format: {}", e))
    }

    /// Decrypt the Project Master Key for an authorized member
    pub fn unlock_master_key(
        store: &MeshVaultStore,
        member_name: &str,
        member_passphrase: &str,
    ) -> Result<[u8; 32], String> {
        let member = store.members.get(member_name).ok_or_else(|| {
            format!(
                "Member '{}' is not registered in this mesh vault.",
                member_name
            )
        })?;

        let salt_bytes = member
            .salt_b64
            .as_deref()
            .and_then(|s| Self::decode_b64(s).ok());
        let key_bytes = Self::derive_key(member_passphrase, salt_bytes.as_deref());
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let enc_mk = Self::decode_b64(&member.encrypted_master_key_b64)?;
        let nonce = Self::decode_b64(&member.nonce_b64)?;

        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), enc_mk.as_ref())
            .map_err(|_| {
                "Access Denied: Invalid member passphrase or corrupted key entry.".to_string()
            })?;

        if decrypted.len() != 32 {
            return Err("Decrypted master key is corrupted.".to_string());
        }

        let mut mk = [0u8; 32];
        mk.copy_from_slice(&decrypted);
        Ok(mk)
    }

    /// Decrypt project secrets map using member credentials
    pub fn decrypt_secrets(
        store: &MeshVaultStore,
        member_name: &str,
        member_passphrase: &str,
    ) -> Result<HashMap<String, String>, String> {
        let master_key = Self::unlock_master_key(store, member_name, member_passphrase)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));

        let enc_payload = Self::decode_b64(&store.encrypted_payload_b64)?;
        let nonce = Self::decode_b64(&store.payload_nonce_b64)?;

        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), enc_payload.as_ref())
            .map_err(|e| format!("Failed to decrypt mesh payload: {}", e))?;

        let json_str =
            String::from_utf8(decrypted).map_err(|e| format!("Payload utf8 error: {}", e))?;
        let map: HashMap<String, String> =
            serde_json::from_str(&json_str).map_err(|e| format!("Payload parse error: {}", e))?;
        Ok(map)
    }

    /// Add a new team member to the mesh vault (authorizing them with their passphrase)
    pub fn add_member(
        repo_path: Option<&Path>,
        admin_name: &str,
        admin_passphrase: &str,
        new_member_name: &str,
        new_member_passphrase: &str,
    ) -> Result<(), String> {
        let mut store = Self::read_store(repo_path)?;
        let master_key = Self::unlock_master_key(&store, admin_name, admin_passphrase)?;

        // Encrypt the project master key for the new member using Argon2id with random 16-byte salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let new_member_key_bytes = Self::derive_key(new_member_passphrase, Some(&salt));
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&new_member_key_bytes));

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let enc_mk = cipher
            .encrypt(Nonce::from_slice(&nonce), master_key.as_ref())
            .map_err(|e| format!("Failed to encrypt master key for new member: {}", e))?;

        let mut hasher = Sha256::new();
        hasher.update(new_member_passphrase.as_bytes());
        let fp = format!("{:x}", hasher.finalize())[..12].to_string();

        let member = MeshMember {
            name: new_member_name.to_string(),
            salt_b64: Some(Self::encode_b64(&salt)),
            public_key_fingerprint: fp,
            encrypted_master_key_b64: Self::encode_b64(&enc_mk),
            nonce_b64: Self::encode_b64(&nonce),
        };

        store.members.insert(new_member_name.to_string(), member);

        let vault_path = Self::get_mesh_vault_path(repo_path);
        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| format!("Serialization error: {}", e))?;
        Self::save_mesh_vault(&vault_path, &json)?;
        Ok(())
    }

    /// Set or update a secret in the shared mesh vault
    pub fn set_secret(
        repo_path: Option<&Path>,
        member_name: &str,
        member_passphrase: &str,
        key: &str,
        value: &str,
    ) -> Result<(), String> {
        let mut store = Self::read_store(repo_path)?;
        let master_key = Self::unlock_master_key(&store, member_name, member_passphrase)?;
        let mut secrets = Self::decrypt_secrets(&store, member_name, member_passphrase)?;

        secrets.insert(key.to_string(), value.to_string());

        let json_payload =
            serde_json::to_string(&secrets).map_err(|e| format!("JSON error: {}", e))?;
        let master_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));

        let mut payload_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut payload_nonce);
        let enc_payload = master_cipher
            .encrypt(Nonce::from_slice(&payload_nonce), json_payload.as_bytes())
            .map_err(|e| format!("Encryption error: {}", e))?;

        store.encrypted_payload_b64 = Self::encode_b64(&enc_payload);
        store.payload_nonce_b64 = Self::encode_b64(&payload_nonce);

        let vault_path = Self::get_mesh_vault_path(repo_path);
        let json = serde_json::to_string_pretty(&store)
            .map_err(|e| format!("Serialization error: {}", e))?;
        Self::save_mesh_vault(&vault_path, &json)?;
        Ok(())
    }

    /// Simple base64 encode using standard hex/base64 without heavy external dependencies
    pub fn encode_b64(data: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(b2 & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Simple base64 decode
    pub fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
        let input = input.trim_end_matches('=');
        let mut out = Vec::new();
        let bytes: Vec<u8> = input
            .chars()
            .filter_map(|c| match c {
                'A'..='Z' => Some(c as u8 - b'A'),
                'a'..='z' => Some(c as u8 - b'a' + 26),
                '0'..='9' => Some(c as u8 - b'0' + 52),
                '+' => Some(62),
                '/' => Some(63),
                _ => None,
            })
            .collect();

        for chunk in bytes.chunks(4) {
            if chunk.len() >= 2 {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
            }
            if chunk.len() >= 3 {
                out.push(((chunk[1] & 15) << 4) | (chunk[2] >> 2));
            }
            if chunk.len() >= 4 {
                out.push(((chunk[2] & 3) << 6) | chunk[3]);
            }
        }
        Ok(out)
    }

    /// Helper to retrieve a passphrase from CLI arguments (with security warning),
    /// environment variable, or hidden interactive prompt.
    fn get_passphrase(
        explicit_arg: Option<&str>,
        env_var: &str,
        prompt: &str,
    ) -> Result<String, String> {
        if let Some(pass) = explicit_arg {
            if !pass.is_empty() && pass != "-" {
                eprintln!(
                    "⚠️  Warning: Passing passwords via CLI arguments is insecure and visible in process listings."
                );
                eprintln!(
                    "   Consider using an interactive prompt or setting the {} environment variable.",
                    env_var
                );
                return Ok(pass.to_string());
            }
        }
        if let Ok(env_val) = std::env::var(env_var) {
            if !env_val.is_empty() {
                return Ok(env_val);
            }
        }
        crate::vault::read_password_hidden(prompt)
            .map_err(|e| format!("Failed to read password from terminal: {}", e))
    }

    /// CLI Handler for `secretguard mesh`
    pub fn run_cli(args: &[String]) {
        if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
            eprintln!(
                r#"secretguard mesh - Zero-Knowledge P2P Team Vault Mesh

USAGE:
    secretguard mesh <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    init <PROJECT> [USER] [PASSWORD]      Initializes a team mesh vault (.secretguard/mesh.vault)
    add <ADMIN> [ADMIN_PASS] <USER> [PWD] Authorizes a new team member to access the vault
    members                               Lists all authorized team members & key fingerprints
    set <USER> [PASSWORD] <KEY> [VALUE]   Encrypts and stores a shared secret in the mesh vault
    get <USER> [PASSWORD] <KEY>           Decrypts and prints a specific shared secret
    list <USER> [PASSWORD]                Lists all secret keys currently stored in the mesh
    export-env <USER> [PASSWORD]          Exports decrypted secrets as a format-ready .env string

SECURITY NOTE:
    Passwords can be provided via interactive hidden prompt (default), environment variable
    (SECRETGUARD_MESH_PASSWORD), or CLI argument (strongly discouraged).
"#
            );
            return;
        }

        match args[0].as_str() {
            "init" => {
                if args.len() < 2 {
                    eprintln!(
                        "Usage: secretguard mesh init <PROJECT_NAME> [CREATOR_NAME] [CREATOR_PASS]"
                    );
                    std::process::exit(2);
                }
                let project_name = &args[1];
                let creator_name = if args.len() >= 3 {
                    args[2].clone()
                } else {
                    std::env::var("USER")
                        .or_else(|_| std::env::var("USERNAME"))
                        .unwrap_or_else(|_| "admin".to_string())
                };

                let pass = match Self::get_passphrase(
                    args.get(3).map(|s| s.as_str()),
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter master passphrase for creator '{}': ", creator_name),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                match Self::init_mesh(&creator_name, &pass, project_name, None) {
                    Ok(path) => {
                        println!("🎉 Zero-Knowledge Mesh Vault initialized successfully!");
                        println!("📁 Stored at: \x1b[32m{}\x1b[0m", path.display());
                        println!(
                            "👤 Initialized with admin member: \x1b[1m{}\x1b[0m",
                            creator_name
                        );
                        println!(
                            "💡 You can commit .secretguard/mesh.vault safely to your repository."
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Mesh initialization failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "add" => {
                if args.len() < 3 {
                    eprintln!("Usage: secretguard mesh add <ADMIN_NAME> [ADMIN_PASS] <NEW_USER> [NEW_USER_PASS]");
                    std::process::exit(2);
                }
                let (admin_name, admin_pass_arg, new_user_name, new_user_pass_arg) =
                    if args.len() >= 5 {
                        (
                            &args[1],
                            Some(args[2].as_str()),
                            &args[3],
                            Some(args[4].as_str()),
                        )
                    } else if args.len() == 4 {
                        (&args[1], Some(args[2].as_str()), &args[3], None)
                    } else {
                        (&args[1], None, &args[2], None)
                    };

                let admin_pass = match Self::get_passphrase(
                    admin_pass_arg,
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter passphrase for admin '{}': ", admin_name),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                let new_user_pass = match Self::get_passphrase(
                    new_user_pass_arg,
                    "SECRETGUARD_NEW_MEMBER_PASSWORD",
                    &format!("Enter passphrase for new member '{}': ", new_user_name),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                match Self::add_member(None, admin_name, &admin_pass, new_user_name, &new_user_pass)
                {
                    Ok(_) => {
                        println!(
                            "✅ Team member '\x1b[32m{}\x1b[0m' successfully added to the mesh vault!",
                            new_user_name
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to add member: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "members" => match Self::read_store(None) {
                Ok(store) => {
                    println!(
                        "🕸️ Project Mesh: \x1b[1m{}\x1b[0m ({} members)",
                        store.project_name,
                        store.members.len()
                    );
                    for (name, m) in &store.members {
                        println!(
                            "  • \x1b[33m{}\x1b[0m [Fingerprint: {}]",
                            name, m.public_key_fingerprint
                        );
                    }
                }
                Err(e) => {
                    eprintln!("❌ {}", e);
                    std::process::exit(1);
                }
            },
            "set" => {
                if args.len() < 3 {
                    eprintln!("Usage: secretguard mesh set <USER> [PASSWORD] <KEY> [VALUE]");
                    std::process::exit(2);
                }
                let (user, pass_arg, key, val_arg) = if args.len() >= 5 {
                    (
                        &args[1],
                        Some(args[2].as_str()),
                        &args[3],
                        Some(args[4].as_str()),
                    )
                } else if args.len() == 4 {
                    (&args[1], None, &args[2], Some(args[3].as_str()))
                } else {
                    (&args[1], None, &args[2], None)
                };

                let pass = match Self::get_passphrase(
                    pass_arg,
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter passphrase for '{}': ", user),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                let val = if let Some(v) = val_arg {
                    v.to_string()
                } else {
                    match crate::vault::read_password_hidden(&format!(
                        "Enter secret value for '{}': ",
                        key
                    )) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("❌ Failed to read secret value: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                match Self::set_secret(None, user, &pass, key, &val) {
                    Ok(_) => {
                        println!(
                            "🔒 Secret '\x1b[32m{}\x1b[0m' encrypted and saved to team mesh vault.",
                            key
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to store secret: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "get" => {
                if args.len() < 3 {
                    eprintln!("Usage: secretguard mesh get <USER> [PASSWORD] <KEY>");
                    std::process::exit(2);
                }
                let (user, pass_arg, key) = if args.len() >= 4 {
                    (&args[1], Some(args[2].as_str()), &args[3])
                } else {
                    (&args[1], None, &args[2])
                };

                let pass = match Self::get_passphrase(
                    pass_arg,
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter passphrase for '{}': ", user),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                match Self::read_store(None) {
                    Ok(store) => match Self::decrypt_secrets(&store, user, &pass) {
                        Ok(secrets) => {
                            if let Some(val) = secrets.get(key) {
                                println!("{}", val);
                            } else {
                                eprintln!("Secret '{}' not found in mesh vault.", key);
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "list" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard mesh list <USER> [PASSWORD]");
                    std::process::exit(2);
                }
                let user = &args[1];
                let pass_arg = args.get(2).map(|s| s.as_str());
                let pass = match Self::get_passphrase(
                    pass_arg,
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter passphrase for '{}': ", user),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                match Self::read_store(None) {
                    Ok(store) => match Self::decrypt_secrets(&store, user, &pass) {
                        Ok(secrets) => {
                            println!("📋 Stored Team Secrets ({} items):", secrets.len());
                            for k in secrets.keys() {
                                println!("  • \x1b[36m{}\x1b[0m", k);
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "export-env" => {
                if args.len() < 2 {
                    eprintln!("Usage: secretguard mesh export-env <USER> [PASSWORD]");
                    std::process::exit(2);
                }
                let user = &args[1];
                let pass_arg = args.get(2).map(|s| s.as_str());
                let pass = match Self::get_passphrase(
                    pass_arg,
                    "SECRETGUARD_MESH_PASSWORD",
                    &format!("Enter passphrase for '{}': ", user),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                };

                match Self::read_store(None) {
                    Ok(store) => match Self::decrypt_secrets(&store, user, &pass) {
                        Ok(secrets) => {
                            for (k, v) in &secrets {
                                println!("{}={}", k, v);
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ {}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                eprintln!("Unknown subcommand: {}", args[0]);
                std::process::exit(2);
            }
        }
    }
}
