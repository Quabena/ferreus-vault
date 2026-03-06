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
//! - Atomic vault writes
//! - Encryption orchestration
//! - Vault loading and validation
//!
//! Security goals:
//! - Prevent corruption on crash/power loss
//! - Avoid plaintext memory persistence
//! - Maintain audit-friendly behaviour

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs /*option*/};

//use bincode::options;

use crate::crypto::{EncryptedVault, MasterKey};
use crate::errors::VaultError;
use crate::vault::VaultData;

/// File extension for vault files
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

    /* ------------------- Vault Creation --------------- */

    pub fn create_vault(
        &self,
        master_password: &str,
        vault_data: &VaultData,
    ) -> Result<(), VaultError> {
        let master_key = MasterKey::from_password(master_password)?;

        // Serialize vault
        let serialized =
            bincode::serialize(vault_data).map_err(|_| VaultError::SerializationError)?;

        // Encrypt vault
        let encrypted = EncryptedVault::encrypt(&serialized, &master_key)?;

        // Save encrypted vault
        self.atomic_write(&encrypted.to_bytes()?)
    }

    /* --------------------- Vault Loading --------------------- */

    pub fn load_vault(&self, master_password: &str) -> Result<(VaultData, MasterKey), VaultError> {
        let vault_bytes = fs::read(&self.vault_path).map_err(VaultError::IoError)?;

        let encrypted_vault =
            EncryptedVault::from_bytes(&vault_bytes).map_err(|_| VaultError::SerializationError)?;

        // Validate vault version early
        if encrypted_vault.version != EncryptedVault::CURRENT_VERSION {
            return Err(VaultError::CorruptedVault);
        }

        let master_key =
            MasterKey::from_password_with_salt(master_password, &encrypted_vault.salt)?;

        let decrypted_bytes = encrypted_vault.decrypt(&master_key)?;

        let vault_data: VaultData =
            bincode::deserialize(&decrypted_bytes).map_err(|_| VaultError::SerializationError)?;

        Ok((vault_data, master_key))
    }

    /* ------------------- Vault Save ----------------------- */

    pub fn save_vault(&self, encrypted: &[u8]) -> Result<(), VaultError> {
        self.atomic_write(encrypted)
    }

    /* ------------------- Atomic Write ----------------------- */

    fn atomic_write(&self, data: &[u8]) -> Result<(), VaultError> {
        let temp_path = self.vault_path.with_extension("tmp");

        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        // let mut file = OpenOptions::new().create(true).write(true).truncate(true);

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);

        #[cfg(unix)]
        {
            use std::{option, os::unix::fs::OpenOptionExt};
            options.mode(0o600);
        }

        let mut file = options.open(&temp_path).map_err(VaultError::IoError)?;

        file.write_all(data).map_err(VaultError::IoError)?;

        file.flush().map_err(VaultError::IoError)?;

        file.sync_all().map_err(VaultError::IoError)?;

        drop(file);

        // Atomic replace
        fs::rename(&temp_path, &self.vault_path).map_err(VaultError::IoError)?;

        // Ensure directory metadata is flushed (important for crash safety)
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

    /* ------------------- Helpers ----------------------- */

    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    pub fn path(&self) -> &Path {
        &self.vault_path
    }
}

/* ------------------- Backup Filename Utility ----------------------- */

pub fn generate_backup_filename(base_path: &Path) -> PathBuf {
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

    let mut counter = 1;

    while backup_path.exists() {
        backup_path = base_path.with_file_name(format!(
            "{}_{}_backup_{}{}",
            base_name, timestamp, counter, VAULT_EXTENSION
        ));

        counter += 1;
    }

    backup_path
}

/* ------------------- Vault Deletion ----------------------- */

pub fn delete_vault_file(path: &Path) -> Result<(), VaultError> {
    fs::remove_file(path).map_err(VaultError::IoError)?;
    Ok(())
}
