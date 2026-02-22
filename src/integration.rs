#[cfg(test)]
mod tests {
    use ferreus_vault::*;
    use serial_test::serial;
    use tempfile::NamedTempFile;

    /* ----------------------------------------Vault LifeCycle -------------------------- */

    #[test]
    #[serial]
    fn vault_creation_unlock_and_lock_cycle() {
        let temp = NamedTempFile::new().expect("temp file");
        let path = temp.path();

        let mut manager = VaultManager::new(path);

        let strong = "StrongPassword123!@#";

        assert!(validate_master_password("weak").is_err());
        assert!(validate_master_password(strong).is_ok());

        manager.create_vault(strong).expect("create vault");

        assert!(!manager.is_unlocked());

        assert!(manager.unlock_vault("WrongPassword").is_err());

        manager.unlock_vault(strong).expect("unlock");
        assert!(manager.is_unlocked());

        manager.lock_vault();
        assert!(!manager.is_unlocked());
    }

    /* ----------------------------------------Entry Persistence -------------------------- */
    #[test]
    #[serial]
    fn entry_create_update_and_persist() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let mut manager = VaultManager::new(path);
        let password = "TestPassword123!@#";

        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();

        manager
            .with_vault_data(|vault| {
                vault.add_entry(vault::PasswordEntry::new(
                    "Gmail".into(),
                    "user@gmail.com".into(),
                    "secret".into(),
                    "notes".into(),
                ));
            })
            .unwrap();

        manager
            .with_vault_data(|vault| {
                vault
                    .update_entry(
                        0,
                        Some("Google Mail".into()),
                        Some("new@gmail.com".into()),
                        Some("newpass".into()),
                        Some("updated".into()),
                    )
                    .unwrap();
            })
            .unwrap();

        manager.save_vault().unwrap();
        manager.lock_vault();
        manager.unlock_vault(password).unwrap();

        let name = manager
            .with_vault_data(|vault| vault.get_entry(0).unwrap().account_name.clone())
            .unwrap();

        assert_eq!(name, "Google Mail");
    }

    /* ----------------------------------------Temper Detection -------------------------- */

    #[test]
    #[serial]
    fn tampered_vault_rejected() {
        use std::fs;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let mut manager = VaultManager::new(path);
        let password = "TamperTestPassword123!";

        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();
        manager.save_vault().unwrap();

        // Corrupt vault file
        let mut bytes = fs::read(path).unwrap();
        bytes[bytes.len() / 2] ^= 0xFF;
        fs::write(path, bytes).unwrap();

        assert!(manager.unlock_vault(password).is_err());
    }

    /* ----------------------------------------Password Strength Heuristic-------------------------- */

    #[test]
    fn password_strength_scoring() {
        assert!(crypto::estimate_password_strength("password") < 30.0);
        assert!(crypto::estimate_password_strength("Password123") > 50.0);
        assert!(crypto::estimate_password_strength("Very$tr0ngP@ssw0rd!WithManyChars") > 80.0);
    }

    /* ----------------------------------------Auto Lock-------------------------- */

    #[test]
    #[serial]
    fn auto_lock_trigger_behaviour() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let mut manager = VaultManager::new(path);
        let password = "AutoLockPassword123!";

        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();

        manager.set_auto_lock_timeout(std::time::Duration::from_millis(100));

        std::thread::sleep(std::time::Duration::from_millis(150));

        assert!(manager.should_auto_lock());

        manager.lock_vault();
        assert!(!manager.is_unlocked());
    }

    /* ----------------------------------------Secure Random Generation  -------------------------- */

    #[test]
    fn secure_random_generation() {
        use ferreus_vault::memory::generate_secure_random_string;

        let random = generate_secure_random_string(32);

        assert_eq!(random.len(), 32);
        assert!(random.chars().all(|c| c.is_alphanumeric()));
    }
}
