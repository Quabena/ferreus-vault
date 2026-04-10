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

//! Vault file persistence layer
//!
//! Responsibilities:
//! - Atomic vault writes (write-to-temp → fsync → rename)
//! - Encryption orchestration via [`crate::crypto`]
//! - Vault loading, version validation, and decryption
//!
//! Security goals:
//! - Prevent corruption on crash or power loss via atomic rename
//! - Avoid plaintext persistence — only ciphertext is written to disk
//! - Maintain a single, auditable code path for both creation and loading
//!
//! # KDF contract
//! [`VaultStorage::create_vault`] and [`VaultStorage::load_vault`] both reach
//! the same KDF via [`MasterKey::from_password_with_salt`] and
//! [`MasterKey::new_from_password`] respectively. The parameters live in a
//! single place (`crypto::ARGON2_*` constants) — changing them there updates
//! both paths atomically.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::{EncryptedVault, MasterKey};
use crate::errors::VaultError;
use crate::vault::VaultData;

/// File extension for vault files (includes the leading dot).
pub const VAULT_EXTENSION: &str = ".sark";

/// Handles vault file operations.
pub struct VaultStorage {
    vault_path: PathBuf,
}

impl VaultStorage {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            vault_path: path.as_ref().to_path_buf(),
        }
    }

    /* ------------------- Vault Creation ---------------------------------- */

    /// Creates and persists a new, empty vault encrypted with `master_password`.
    ///
    /// A fresh random salt is generated internally by [`MasterKey::new_from_password`],
    /// guaranteeing that every new vault has a unique salt even when the same
    /// password is reused.
    pub fn create_vault(
        &self,
        master_password: &str,
        vault_data: &VaultData,
    ) -> Result<(), VaultError> {
        // Derive key with a freshly-generated random salt.
        let master_key = MasterKey::new_from_password(master_password)?;

        let serialized =
            bincode::serialize(vault_data).map_err(|_| VaultError::SerializationError)?;

        let encrypted = EncryptedVault::encrypt(&serialized, &master_key)?;

        self.atomic_write(&encrypted.to_bytes()?)
    }

    /* ------------------- Vault Loading ----------------------------------- */

    /// Loads, authenticates, and decrypts a vault file.
    ///
    /// Returns the decrypted [`VaultData`] together with the re-derived
    /// [`MasterKey`] so that `save_vault` can re-encrypt without asking the
    /// user for the password a second time.
    ///
    /// # KDF symmetry
    /// The salt embedded in the encrypted vault container is extracted and
    /// passed to [`MasterKey::from_password_with_salt`] — the same function
    /// (and therefore the same parameters) used by [`Self::create_vault`].
    pub fn load_vault(&self, master_password: &str) -> Result<(VaultData, MasterKey), VaultError> {
        let vault_bytes = fs::read(&self.vault_path).map_err(VaultError::IoError)?;

        let encrypted_vault = EncryptedVault::from_bytes(&vault_bytes)
            .map_err(|_| VaultError::CorruptedVault)?;

        if encrypted_vault.version != EncryptedVault::CURRENT_VERSION {
            return Err(VaultError::CorruptedVault);
        }

        // Re-derive the key using the salt stored in the vault file.
        let master_key =
            MasterKey::from_password_with_salt(master_password, &encrypted_vault.salt)
                .map_err(|_| VaultError::InvalidPassword)?;

        let decrypted_bytes = encrypted_vault
            .decrypt(&master_key)
            .map_err(|_| VaultError::InvalidPassword)?;

        if decrypted_bytes.is_empty() {
            return Err(VaultError::CorruptedVault);
        }

        let vault_data: VaultData =
            bincode::deserialize(&decrypted_bytes).map_err(|_| VaultError::CorruptedVault)?;

        Ok((vault_data, master_key))
    }

    /* ------------------- Vault Save -------------------------------------- */

    /// Persists a pre-encrypted vault payload atomically.
    pub fn save_vault(&self, encrypted: &[u8]) -> Result<(), VaultError> {
        self.atomic_write(encrypted)
    }

    /* ------------------- Atomic Write ------------------------------------ */

    /// Writes `data` to the vault path atomically using a temp-file + rename.
    ///
    /// The sequence is:
    /// 1. Write to `<path>.tmp` (mode 0o600 on Unix).
    /// 2. `fsync` the temp file.
    /// 3. Create a timestamped backup of the *existing* vault (if one exists).
    /// 4. `rename` temp → final path (atomic on POSIX).
    /// 5. `fsync` the parent directory (crash-safe on Linux).
    ///
    /// The backup is created **after** the new data is durably fsynced but
    /// **before** the rename, so a power-loss between steps 3 and 4 leaves
    /// both the old vault and the new temp file intact.
    fn atomic_write(&self, data: &[u8]) -> Result<(), VaultError> {
        let temp_path = self.vault_path.with_extension("tmp");

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path).map_err(VaultError::IoError)?;
        file.write_all(data).map_err(VaultError::IoError)?;
        file.flush().map_err(VaultError::IoError)?;
        file.sync_all().map_err(VaultError::IoError)?;
        drop(file);

        // Backup the existing vault only after the new data has been fsynced.
        if self.vault_path.exists() {
            let backup = generate_backup_path(&self.vault_path);
            fs::copy(&self.vault_path, backup).map_err(VaultError::IoError)?;
        }

        // Atomic replace on POSIX; best-effort on Windows.
        fs::rename(&temp_path, &self.vault_path).map_err(VaultError::IoError)?;

        // Flush the directory entry so the rename survives a kernel crash.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(parent) = self.vault_path.parent() {
                let dir = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY)
                    .open(parent)
                    .map_err(VaultError::IoError)?;
                dir.sync_all().map_err(VaultError::IoError)?;
            }
        }

        Ok(())
    }

    /* ------------------- Helpers ----------------------------------------- */

    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    pub fn path(&self) -> &Path {
        &self.vault_path
    }
}

/* ------------------- Backup Path Utility --------------------------------- */

/// Generates a timestamped backup filename adjacent to `base_path`.
///
/// If a file with the generated name already exists, a numeric suffix is
/// appended until a free name is found.
pub fn generate_backup_path(base_path: &Path) -> PathBuf {
    use chrono::Local;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let base_name = base_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    let mut backup_path = base_path.with_file_name(format!(
        "{}_{}_backup{}",
        base_name, timestamp, VAULT_EXTENSION
    ));

    let mut counter: u32 = 1;
    while backup_path.exists() {
        backup_path = base_path.with_file_name(format!(
            "{}_{}_backup_{}{}",
            base_name, timestamp, counter, VAULT_EXTENSION
        ));
        counter += 1;
    }

    backup_path
}

/* ------------------- Vault Deletion -------------------------------------- */

/// Removes the vault file at `path`.
///
/// Callers are responsible for ensuring the vault is locked before calling
/// this function. This does not perform a secure overwrite — if a secure
/// delete is required, the caller must zero the file contents before removal.
pub fn delete_vault_file(path: &Path) -> Result<(), VaultError> {
    fs::remove_file(path).map_err(VaultError::IoError)
}
