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
use std::sync::{Arc, Mutex, MutexGuard};
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

    failed_attempts: u32,
    lockout_until: Option<Instant>,
}

impl VaultManager {
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault_data: Arc::new(Mutex::new(None)),
            master_key: Arc::new(Mutex::new(None)),
            storage: VaultStorage::new(vault_path),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Instant::now(),
            failed_attempts: 0,
            lockout_until: None,
        }
    }

    /* ------------------ Vault Creation -------------------------- */

    pub fn create_vault(&self, master_password: &str) -> Result<(), VaultError> {
        if self.storage.vault_exists() {
            return Err(VaultError::CryptoError("Vault already exists".into()));
        }

        let vault_data = VaultData::new();
        self.storage.create_vault(master_password, &vault_data)
    }

    /* ------------------ Unlocking -------------------------- */

    pub fn unlock_vault(&mut self, password: &str) -> Result<(), VaultError> {
        let now = Instant::now();

        // Hard lockout check
        if let Some(until) = self.lockout_until {
            if now < until {
                return Err(VaultError::CryptoError(
                    "Too many failed attempts. Try again later.".into(),
                ));
            }

            self.lockout_until = None;
        }

        // Attempt unlock
        if self.try_unlock(password).is_ok() {
            self.failed_attempts = 0;
            self.lockout_until = None;
            return Ok(());
        }

        // Failure handling
        self.failed_attempts += 1;

        // Exponential backoff
        let delay = 2u64
            .saturating_pow(self.failed_attempts.saturating_sub(1))
            .min(15);

        std::thread::sleep(Duration::from_secs(delay));

        // Hard lockout
        if self.failed_attempts >= 5 {
            self.lockout_until = Some(now + Duration::from_secs(30));
        }

        Err(VaultError::CryptoError("Invalid credentials".into()))
    }

    fn try_unlock(&mut self, password: &str) -> Result<(), VaultError> {
        let (vault_data, master_key) = self.storage.load_vault(password)?;

        {
            let mut data_lock = self.lock_data()?;
            let mut key_lock = self.lock_key()?;

            *data_lock = Some(vault_data);
            *key_lock = Some(master_key);
        }

        self.touch();
        Ok(())
    }

    /* ------------------ Locking -------------------------- */

    pub fn lock_vault(&self) {
        if let Ok(mut data) = self.vault_data.lock() {
            *data = None;
        }

        if let Ok(mut key) = self.master_key.lock() {
            *key = None;
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault_data.lock().map(|v| v.is_some()).unwrap_or(false)
    }

    /* ------------------ Persistence -------------------------- */

    pub fn save_vault(&mut self) -> Result<(), VaultError> {
        let encrypted_bytes = {
            let data_guard = self.lock_data()?;
            let key_guard = self.lock_key()?;

            match (&*data_guard, &*key_guard) {
                (Some(data), Some(key)) => {
                    // Serialize vault
                    let serialized =
                        bincode::serialize(data).map_err(|_| VaultError::SerializationError)?;

                    // Encrypt vault
                    let encrypted = crate::crypto::EncryptedVault::encrypt(&serialized, key)?;

                    // Convert to file bytes
                    encrypted
                        .to_bytes()
                        .map_err(|_| VaultError::SerializationError)?
                }
                _ => return Err(VaultError::VaultLocked),
            }
        };

        // Persist atomically
        self.storage.save_vault(&encrypted_bytes)?;

        self.touch();
        Ok(())
    }

    /* ------------------ Vault Operations -------------------------- */

    pub fn with_vault_data<F, T>(&mut self, operation: F) -> Result<T, VaultError>
    where
        F: FnOnce(&mut VaultData) -> T,
    {
        let result = {
            let mut guard = self.lock_data()?;

            match &mut *guard {
                Some(data) => Ok(operation(data)),
                None => Err(VaultError::VaultLocked),
            }
        };

        if result.is_ok() {
            self.touch();
        }

        result
    }

    /* ------------------ Auto-lock Policy -------------------------- */

    pub fn should_auto_lock(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed() >= self.auto_lock_timeout
    }

    pub fn set_auto_lock_timeout(&mut self, timeout: Duration) {
        self.auto_lock_timeout = timeout;
    }

    pub fn auto_lock_timeout(&self) -> Option<Duration> {
        Some(self.auto_lock_timeout)
    }

    /* ------------------ Helpers -------------------------- */

    fn lock_data(&self) -> Result<MutexGuard<'_, Option<VaultData>>, VaultError> {
        self.vault_data.lock().map_err(|_| VaultError::VaultLocked)
    }

    fn lock_key(&self) -> Result<MutexGuard<'_, Option<MasterKey>>, VaultError> {
        self.master_key.lock().map_err(|_| VaultError::VaultLocked)
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn vault_path(&self) -> &Path {
        self.storage.path()
    }

    pub fn estimate_password_strength(password: &str) -> f64 {
        estimate_password_strength(password)
    }
}

impl Drop for VaultManager {
    fn drop(&mut self) {
        self.lock_vault();
    }
}

/* ---------------------------- Password Validation -------------------------- */

pub fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.len() < 12 {
        return Err(VaultError::InvalidPassword);
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let categories = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();

    if categories < 3 {
        return Err(VaultError::InvalidPassword);
    }

    Ok(())
}
