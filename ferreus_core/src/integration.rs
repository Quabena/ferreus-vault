// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferreus Vault Contributors
//
// This file is part of Ferreus Vault.
//
// Ferreus Vault is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 only,
// as published by the Free Software Foundation.
//
// Ferreus Vault is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

/// Integration tests for FerreusVault
///
/// These tests exercise the full lifecycle of the vault through the public API.
/// They are intentionally coarse-grained: each test covers a user-visible
/// behaviour rather than an implementation detail.
///
/// Run with:
/// ```
/// cargo test --test integration
/// ```
#[cfg(test)]
mod tests {
    // The library crate is named `ferreus_vault`, not `ferreus_core`.
    use ferreus_vault::*;
    use serial_test::serial;
    use tempfile::NamedTempFile;

    /* ------------------- Vault lifecycle --------------------------------- */

    #[test]
    #[serial]
    fn vault_creation_unlock_and_lock_cycle() {
        let temp = NamedTempFile::new().expect("failed to create temp file");
        let path = temp.path();

        let mut manager = VaultManager::new(path);
        let strong_password = "StrongPassword123!@#";

        // Weak passwords must be rejected before the vault is created.
        assert!(validate_master_password("weak").is_err());
        assert!(validate_master_password(strong_password).is_ok());

        manager.create_vault(strong_password).expect("vault creation failed");
        assert!(!manager.is_unlocked(), "vault should be locked after creation");

        // Wrong password must fail.
        assert!(
            manager.unlock_vault("WrongPassword").is_err(),
            "wrong password should be rejected"
        );

        // Correct password must succeed.
        manager.unlock_vault(strong_password).expect("unlock failed");
        assert!(manager.is_unlocked());

        manager.lock_vault();
        assert!(!manager.is_unlocked());
    }

    /* ------------------- Entry persistence ------------------------------- */

    #[test]
    #[serial]
    fn entry_create_update_and_persist() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let password = "TestPassword123!@#";

        let mut manager = VaultManager::new(path);
        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();

        // Add an entry.
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

        // Update the entry.
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

        // Persist, lock, and re-open.
        manager.save_vault().unwrap();
        manager.lock_vault();
        manager.unlock_vault(password).unwrap();

        let name = manager
            .with_vault_data(|vault| vault.get_entry(0).unwrap().account_name.clone())
            .unwrap();

        assert_eq!(name, "Google Mail");
    }

    /* ------------------- Tamper detection -------------------------------- */

    #[test]
    #[serial]
    fn tampered_vault_rejected() {
        use std::fs;

        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let password = "TamperTestPassword123!";

        let mut manager = VaultManager::new(path);
        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();
        manager.save_vault().unwrap();
        manager.lock_vault();

        // Flip a bit in the middle of the ciphertext.
        let mut bytes = fs::read(path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        fs::write(path, bytes).unwrap();

        assert!(
            manager.unlock_vault(password).is_err(),
            "tampered vault must be rejected"
        );
    }

    /* ------------------- Password strength heuristic --------------------- */

    #[test]
    fn password_strength_scoring() {
        assert!(
            crypto::estimate_password_strength("password") < 30.0,
            "weak password should score below 30"
        );
        assert!(
            crypto::estimate_password_strength("Password123") > 50.0,
            "medium password should score above 50"
        );
        assert!(
            crypto::estimate_password_strength("Very$tr0ngP@ssw0rd!WithManyChars") > 80.0,
            "strong password should score above 80"
        );
    }

    /* ------------------- Auto-lock --------------------------------------- */

    #[test]
    #[serial]
    fn auto_lock_trigger_behaviour() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let password = "AutoLockPassword123!";

        let mut manager = VaultManager::new(path);
        manager.create_vault(password).unwrap();
        manager.unlock_vault(password).unwrap();

        manager.set_auto_lock_timeout(std::time::Duration::from_millis(100));

        std::thread::sleep(std::time::Duration::from_millis(150));

        assert!(manager.should_auto_lock(), "auto-lock should trigger after timeout");

        manager.lock_vault();
        assert!(!manager.is_unlocked());
    }

    /* ------------------- Secure random generation ------------------------ */

    #[test]
    fn secure_random_generation() {
        use ferreus_vault::memory::generate_secure_random_string;

        let random = generate_secure_random_string(32);

        assert_eq!(random.len(), 32);
        assert!(random.chars().all(|c| c.is_alphanumeric()));
    }
}
