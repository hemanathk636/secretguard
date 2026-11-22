use secretguard::mesh::MeshManager;
use std::fs;

#[test]
fn test_mesh_vault_full_lifecycle() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sg_mesh_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let admin = "alice";
    let admin_pass = "super-secret-admin-passphrase-999";
    let project = "frontend-core";

    // 1. Init mesh vault
    let vault_file =
        MeshManager::init_mesh(admin, admin_pass, project, Some(&temp_dir)).expect("Init failed");
    assert!(vault_file.exists());

    // 2. Read store & check member
    let store = MeshManager::read_store(Some(&temp_dir)).expect("Read store failed");
    assert_eq!(store.project_name, project);
    assert_eq!(store.members.len(), 1);
    assert!(store.members.contains_key(admin));

    // 3. Set a secret as admin
    MeshManager::set_secret(
        Some(&temp_dir),
        admin,
        admin_pass,
        "DATABASE_URL",
        "postgres://user:pass@127.0.0.1:5432/mydb",
    )
    .expect("Set secret failed");

    // 4. Verify admin can decrypt
    let store2 = MeshManager::read_store(Some(&temp_dir)).unwrap();
    let secrets = MeshManager::decrypt_secrets(&store2, admin, admin_pass).unwrap();
    assert_eq!(
        secrets.get("DATABASE_URL").unwrap(),
        "postgres://user:pass@127.0.0.1:5432/mydb"
    );

    // 5. Add a new member (bob)
    let bob = "bob";
    let bob_pass = "bob-secure-key-12345";
    MeshManager::add_member(Some(&temp_dir), admin, admin_pass, bob, bob_pass)
        .expect("Add member failed");

    // 6. Verify bob can decrypt the exact same secrets
    let store3 = MeshManager::read_store(Some(&temp_dir)).unwrap();
    assert_eq!(store3.members.len(), 2);
    let bob_secrets = MeshManager::decrypt_secrets(&store3, bob, bob_pass).unwrap();
    assert_eq!(
        bob_secrets.get("DATABASE_URL").unwrap(),
        "postgres://user:pass@127.0.0.1:5432/mydb"
    );

    // 7. Bob adds an API key
    MeshManager::set_secret(
        Some(&temp_dir),
        bob,
        bob_pass,
        "STRIPE_KEY",
        "pk_test_sample123",
    )
    .unwrap();

    // 8. Admin reads Bob's added secret
    let store4 = MeshManager::read_store(Some(&temp_dir)).unwrap();
    let admin_secrets = MeshManager::decrypt_secrets(&store4, admin, admin_pass).unwrap();
    assert_eq!(
        admin_secrets.get("STRIPE_KEY").unwrap(),
        "pk_test_sample123"
    );
    assert_eq!(admin_secrets.len(), 2);

    // 9. Unauthorized attempt fails
    let err = MeshManager::decrypt_secrets(&store4, "charlie", "random");
    assert!(err.is_err());

    let wrong_pass_err = MeshManager::decrypt_secrets(&store4, bob, "wrong-passphrase");
    assert!(wrong_pass_err.is_err());

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
