mod common;

use secretguard::ghost::GhostVirtualizer;
use secretguard::SecretGuardEngine;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

static GHOST_TEST_MUTEX: Mutex<()> = Mutex::new(());

fn setup_ghost_env(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("sg_ghost_audit_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    std::env::set_var("SECRETGUARD_DIR", &dir);
    std::env::remove_var("SECRETGUARD_GHOST_PATH");
    dir
}

fn cleanup_ghost_env(dir: &PathBuf) {
    std::env::remove_var("SECRETGUARD_DIR");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_ghost_mapping_count_dedup_and_fresh_session() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("dedup");
    let engine = SecretGuardEngine::new();

    let key1 = format!("sk-proj-{}", "aB3dEf9GhIjK2LmNoPqRsTuVwXyZ012345");
    let input1 = format!("A={}\nB={}\n", key1, key1);
    let (out1, count1) = GhostVirtualizer::try_virtualize_text(&input1, &engine).unwrap();
    assert_eq!(count1, 1);
    assert!(!out1.contains(&key1));

    let sess1 = GhostVirtualizer::try_load_session().unwrap();
    assert_eq!(sess1.mappings.len(), 1);

    let key2 = format!("AKIA{}", "1234567890ABCDEF");
    let input2 = format!("AWS_KEY={}\n", key2);
    let (out2, count2) =
        GhostVirtualizer::try_virtualize_text_with_options(&input2, &engine, true).unwrap();
    assert_eq!(count2, 1);
    assert!(!out2.contains(&key2));

    let sess2 = GhostVirtualizer::try_load_session().unwrap();
    assert_eq!(
        sess2.mappings.len(),
        1,
        "fresh_session=true must not retain prior mappings"
    );

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_contextual_and_db_uri_virtualization() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("context");
    let engine = SecretGuardEngine::new();

    let db_pass = common::synth_db_pass_simple();
    let db_uri = common::synth_db_uri(&db_pass);
    let pass = common::synth_entropy_pass();
    let input = format!("DATABASE_URL={}\nDB_PASSWORD=\"{}\"\n", db_uri, pass);
    let (out, count) =
        GhostVirtualizer::try_virtualize_text_with_options(&input, &engine, true).unwrap();
    assert_eq!(count, 2);
    assert!(!out.contains(&db_pass));
    assert!(!out.contains(&pass));

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_aes_gcm_nonce_uniqueness_and_tamper_rejection() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("crypto");
    let engine = SecretGuardEngine::new();

    let key = format!("ghp_{}", "1234567890abcdef1234567890abcdef1234");
    let input = format!("GH={}\n", key);
    GhostVirtualizer::try_virtualize_text(&input, &engine).unwrap();

    let session_path = GhostVirtualizer::try_get_session_path().unwrap();
    let bytes1 = fs::read(&session_path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes1).contains(&key));

    let sess = GhostVirtualizer::try_load_session().unwrap();
    GhostVirtualizer::save_session(&sess).unwrap();
    let bytes2 = fs::read(&session_path).unwrap();
    assert_ne!(&bytes1[..12], &bytes2[..12], "AES-GCM nonce must be unique");

    let mut tampered = bytes2.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    fs::write(&session_path, &tampered).unwrap();
    assert!(
        GhostVirtualizer::try_load_session().is_err(),
        "Tampered ciphertext/tag must fail authentication"
    );

    fs::write(&session_path, b"short").unwrap();
    assert!(GhostVirtualizer::try_load_session().is_err());

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_purge_removes_session_and_clears_mappings() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("purge");
    let engine = SecretGuardEngine::new();

    let key = format!("sk-proj-{}", "ZyXwVuTsRqPoNmLkJiHgFeDcBa98765432");
    GhostVirtualizer::try_virtualize_text(&format!("K={}", key), &engine).unwrap();
    let session_path = GhostVirtualizer::try_get_session_path().unwrap();
    assert!(session_path.exists());

    GhostVirtualizer::purge_session().unwrap();
    assert!(
        !session_path.exists(),
        "Session file must be removed after purge"
    );
    let after = GhostVirtualizer::try_load_session().unwrap();
    assert!(after.mappings.is_empty());

    GhostVirtualizer::purge_session().unwrap();

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_concurrent_virtualize_preserves_all_mappings() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("concurrent");

    let mut handles = Vec::new();
    for i in 0..4 {
        handles.push(std::thread::spawn(move || {
            let engine = SecretGuardEngine::new();
            let key = format!("AKIA{:04}567890ABCDEF", i * 1111);
            GhostVirtualizer::try_virtualize_text(&format!("K{}={}", i, key), &engine).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let sess = GhostVirtualizer::try_load_session().unwrap();
    assert_eq!(
        sess.mappings.len(),
        4,
        "Concurrent virtualize calls must not overwrite each other's mappings"
    );

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_tokens_are_keyed_hmac_and_preserve_legacy_mappings() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir1 = setup_ghost_env("hmac1");
    let secret = common::synth_openai_key();

    use sha2::{Digest, Sha256};
    let mut legacy_hasher = Sha256::new();
    legacy_hasher.update(b"SECRETGUARD_GHOST_SEED_v1");
    legacy_hasher.update(secret.as_bytes());
    let legacy_hex = format!("{:x}", legacy_hasher.finalize());
    let legacy_token = format!("sk-ghost-{}", &legacy_hex[0..36]);

    let tok1 = GhostVirtualizer::create_ghost_token(&secret);
    assert_ne!(
        tok1, legacy_token,
        "Ghost token must be keyed HMAC, not unkeyed SHA-256"
    );

    let dir2 = setup_ghost_env("hmac2");
    let tok2 = GhostVirtualizer::create_ghost_token(&secret);
    assert_ne!(tok1, tok2);

    let mut legacy_sess = GhostVirtualizer::try_load_session().unwrap();
    legacy_sess
        .mappings
        .insert(legacy_token.clone(), secret.to_string());
    GhostVirtualizer::save_session(&legacy_sess).unwrap();

    let engine = SecretGuardEngine::new();
    let (out, count) =
        GhostVirtualizer::try_virtualize_text(&format!("OPENAI_API_KEY={}", secret), &engine)
            .unwrap();
    assert_eq!(count, 1);
    assert!(
        out.contains(&legacy_token),
        "Existing legacy mapping should be preserved during migration"
    );

    cleanup_ghost_env(&dir2);
    let _ = fs::remove_dir_all(&dir1);
}

#[test]
fn test_ghost_stale_lock_recovery_after_crash() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("stalelock");
    let engine = SecretGuardEngine::new();

    let session_path = GhostVirtualizer::try_get_session_path().unwrap();
    let lock_path = session_path.parent().unwrap().join(".ghost_session.lock");
    {
        let f = fs::File::create(&lock_path).unwrap();
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        let _ = f.set_modified(old_time);
    }
    assert!(lock_path.exists());

    let key = format!("AKIA{}", "9999888877776666");
    let (out, count) = GhostVirtualizer::try_virtualize_text(&format!("K={}", key), &engine)
        .expect("Must recover from stale lockfile");
    assert_eq!(count, 1);
    assert!(!out.contains(&key));
    assert!(!lock_path.exists());

    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_live_pid_lock_not_stolen_beyond_30s() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("livepid");
    let engine = SecretGuardEngine::new();

    let session_path = GhostVirtualizer::try_get_session_path().unwrap();
    let lock_path = session_path.parent().unwrap().join(".ghost_session.lock");
    {
        let mut f = fs::File::create(&lock_path).unwrap();
        use std::io::Write;
        writeln!(f, "pid={}", std::process::id()).unwrap();
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        let _ = f.set_modified(old_time);
    }

    // Because owning PID is still alive, lock MUST NOT be stolen even though mtime > 30s
    let key = format!("AKIA{}", "1111222233334444");
    let res = GhostVirtualizer::try_virtualize_text(&format!("K={}", key), &engine);
    assert!(
        res.is_err(),
        "Lock held by a live PID must not be stolen after 30s"
    );

    let _ = fs::remove_file(&lock_path);
    cleanup_ghost_env(&dir);
}

#[test]
fn test_ghost_persistent_hmac_stability_and_simultaneous_purge() {
    let _guard = GHOST_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = setup_ghost_env("stability");
    let secret = common::synth_openai_key();

    let t1 = GhostVirtualizer::create_ghost_token(&secret);
    let t2 = GhostVirtualizer::create_ghost_token(&secret);
    assert_eq!(t1, t2, "Keyed HMAC token must be stable across calls");

    // Simultaneous virtualize and purge threads must never panic or corrupt
    let mut handles = Vec::new();
    for i in 0..4 {
        handles.push(std::thread::spawn(move || {
            let engine = SecretGuardEngine::new();
            let k = format!("AKIA{:04}567890ABCDEF", i * 1111);
            let _ = GhostVirtualizer::try_virtualize_text(&format!("K={}", k), &engine);
            if i % 2 == 0 {
                let _ = GhostVirtualizer::purge_session();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Session must be either absent or cleanly loadable
    GhostVirtualizer::try_load_session().unwrap();

    cleanup_ghost_env(&dir);
}
