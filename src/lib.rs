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

//! Runtime vault manager
//!
//! Holds unlocked vault state and orchestrates operations
//!
//! Security goals:
//! - Ensure secrets are cleared on lock/drop
//! - Avoid panics during teardown
//! - Maintain strict lock discipline
//! - Provide UI-safe operational interface

pub mod crypto;
pub mod errors;
pub mod memory;
pub mod storage;
pub mod vault;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::{estimate_password_strength, MasterKey};
use crate::errors::VaultError;
use crate::storage::VaultStorage;
use crate::vault::VaultData;

/* ------------------ Vault Manager -------------------------- */

pub struct VaultManager {
    vault_data: Arc<Mutex<Option<VaultData>>>,
    master_key: Arc<Mutex<Option<MasterKey>>>,
    storage: VaultStorage,

    auto_lock_timeout: Duration,
    last_activity: Instant,
}

impl VaultManager {
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault_data: Arc::new(Mutex::new(None)),
            master_key: Arc::new(Mutex::new(None)),
            storage: VaultStorage::new(vault_path),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Instant::now(),
        }
    }

    /* ------------------ Vault Manager -------------------------- */

    pub fn create_vault(&self, master_password: &str) -> Result<(), VaultError> {
        if self.storage.vault_exists() {
            return Err(VaultError::CorruptedVault);
        }

        let vault_data = VaultData::new();
        self.storage.create_vault(master_password, &vault_data)
    }

    /* ------------------ Unlocking -------------------------- */
}
