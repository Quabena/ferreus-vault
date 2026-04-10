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
//! Holds unlocked vault state and orchestrates all operations.
//!
//! Security goals:
//! - Secrets are zeroized on lock and on drop
//! - Brute-force protection via exponential backoff and hard lockout
//! - Strict mutex acquisition order to prevent deadlocks
//! - UI-safe operational interface (no panics in teardown paths)
//!
//! # Mutex acquisition order
//! All code in this module acquires mutexes in the order: **data → key**.
//! Reversing this order anywhere risks a deadlock. Helper methods
//! [`VaultManager::lock_data`] and [`VaultManager::lock_key`] enforce this
//! by being the sole acquisition points.
//!
//! # Brute-force protection limitations
//! The failed-attempt counter and lockout timestamp live on the
//! [`VaultManager`] struct. An attacker who can construct a new `VaultManager`
//! instance (e.g. by restarting the process) resets the counter. For stronger
//! protection, persist the counter and expiry to disk and read it on startup.

pub mod crypto;
pub mod errors;
pub mod logging;
pub mod memory;
pub mod memory_lock;
pub mod storage;
pub mod vault;

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rand::Rng;
use uuid::Uuid;

use crate::crypto::{estimate_password_strength, EncryptedVault, MasterKey};
use crate::errors::VaultError;
use crate::storage::VaultStorage;
use crate::vault::VaultData;

/* ------------------- Vault Manager --------------------------------------- */

pub struct VaultManager {
    /// In-memory plaintext vault contents. `None` when the vault is locked.
    vault_data: Arc<Mutex<Option<VaultData>>>,
    /// In-memory derived master key. `None` when the vault is locked.
    master_key: Arc<Mutex<Option<MasterKey>>>,
    storage: VaultStorage,

    auto_lock_timeout: Duration,
    last_activity: Instant,

    /// Running count of consecutive failed unlock attempts since last success.
    ///
    /// Note: this counter resets if the `VaultManager` is recreated. See the
    /// module-level documentation for a discussion of this limitation.
    failed_attempts: u32,
    /// When `Some(t)`, all unlock attempts before time `t` are rejected.
    lockout_until: Option<Instant>,

    /// Unique identifier for this runtime session, used in audit logging.
    pub session_id: Uuid,
}

impl VaultManager {
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        let session_id = Uuid::new_v4();
        crate::logging::log_security_event(&format!(
            "VaultManager session started: {}",
            session_id
        ));

        Self {
            vault_data: Arc::new(Mutex::new(None)),
            master_key: Arc::new(Mutex::new(None)),
            storage: VaultStorage::new(vault_path),
            auto_lock_timeout: Duration::from_secs(300),
            last_activity: Instant::now(),
            failed_attempts: 0,
            lockout_until: None,
            session_id,
        }
    }

    /* ------------------- Vault Creation ---------------------------------- */

    pub fn create_vault(&self, master_password: &str) -> Result<(), VaultError> {
        if self.storage.vault_exists() {
            return Err(VaultError::CryptoError("Vault already exists".into()));
        }

        let vault_data = VaultData::new();
        self.storage.create_vault(master_password, &vault_data)
    }

    /* ------------------- Unlocking --------------------------------------- */

    /// Attempts to unlock the vault with the supplied password.
    ///
    /// # Timing behaviour
    /// 1. Hard lockout is checked **first** (before any delay).
    /// 2. A random jitter (100–800 ms) is applied to resist timing-based
    ///    enumeration — but only after the lockout check, so a locked-out
    ///    user receives the error immediately.
    /// 3. On failure, an exponential backoff delay is applied (capped at 15 s).
    /// 4. After 5 consecutive failures, a 30-second hard lockout is imposed.
    pub fn unlock_vault(&mut self, password: &str) -> Result<(), VaultError> {
        let now = Instant::now();

        // Check hard lockout before applying any delay.
        if let Some(until) = self.lockout_until {
            if now < until {
                crate::logging::log_security_event(&format!(
                    "session={} unlock rejected: hard lockout active",
                    self.session_id
                ));
                return Err(VaultError::InvalidPassword);
            }
            self.lockout_until = None;
        }

        // Jitter applied after lockout check, before the actual attempt.
        let jitter: u64 = rand::thread_rng().gen_range(100..800);
        std::thread::sleep(Duration::from_millis(jitter));

        match self.try_unlock(password) {
            Ok(()) => {
                self.failed_attempts = 0;
                self.lockout_until = None;
                crate::logging::log_security_event(&format!(
                    "session={} vault unlocked successfully",
                    self.session_id
                ));
                Ok(())
            }
            Err(e) => {
                self.failed_attempts += 1;

                crate::logging::log_security_event(&format!(
                    "session={} unlock failed (attempt {})",
                    self.session_id, self.failed_attempts
                ));

                // Exponential backoff: 0, 1, 2, 4, 8 … capped at 15 seconds.
                let delay = 2u64
                    .saturating_pow(self.failed_attempts.saturating_sub(1))
                    .min(15);
                std::thread::sleep(Duration::from_secs(delay));

                if self.failed_attempts >= 5 {
                    self.lockout_until = Some(Instant::now() + Duration::from_secs(30));
                    crate::logging::log_security_event(&format!(
                        "session={} hard lockout imposed",
                        self.session_id
                    ));
                }

                // Surface the original error rather than a generic string so
                // callers can distinguish wrong-password from I/O failures.
                Err(e)
            }
        }
    }

    fn try_unlock(&mut self, password: &str) -> Result<(), VaultError> {
        let (vault_data, master_key) = self.storage.load_vault(password)?;

        // Acquire in the canonical order: data → key.
        let mut data_lock = self.lock_data()?;
        let mut key_lock = self.lock_key()?;

        *data_lock = Some(vault_data);
        *key_lock = Some(master_key);

        drop(data_lock);
        drop(key_lock);

        self.touch();
        Ok(())
    }

    /* ------------------- Locking ----------------------------------------- */

    /// Locks the vault, zeroizing in-memory secrets.
    pub fn lock_vault(&self) {
        if let Ok(mut data) = self.vault_data.lock() {
            *data = None; // VaultData implements ZeroizeOnDrop
        }
        if let Ok(mut key) = self.master_key.lock() {
            *key = None; // MasterKey implements ZeroizeOnDrop
        }
        crate::logging::log_security_event(&format!(
            "session={} vault locked",
            self.session_id
        ));
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault_data.lock().map(|v| v.is_some()).unwrap_or(false)
    }

    /* ------------------- Persistence ------------------------------------- */

    pub fn save_vault(&mut self) -> Result<(), VaultError> {
        let encrypted_bytes = {
            // Acquire in the canonical order: data → key.
            let data_guard = self.lock_data()?;
            let key_guard = self.lock_key()?;

            match (&*data_guard, &*key_guard) {
                (Some(data), Some(key)) => {
                    let serialized =
                        bincode::serialize(data).map_err(|_| VaultError::SerializationError)?;
                    let encrypted = EncryptedVault::encrypt(&serialized, key)?;
                    encrypted.to_bytes()?
                }
                _ => return Err(VaultError::VaultLocked),
            }
        };

        self.storage.save_vault(&encrypted_bytes)?;
        self.touch();
        Ok(())
    }

    /* ------------------- Vault Operations -------------------------------- */

    /// Provides mutable access to the decrypted vault data via a closure.
    ///
    /// Returns `Err(VaultError::VaultLocked)` if the vault is not currently
    /// unlocked.
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

    /* ------------------- Auto-lock Policy -------------------------------- */

    /// Returns `true` if the vault is unlocked and the idle timeout has elapsed.
    pub fn should_auto_lock(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed() >= self.auto_lock_timeout
    }

    pub fn set_auto_lock_timeout(&mut self, timeout: Duration) {
        self.auto_lock_timeout = timeout;
    }

    pub fn auto_lock_timeout(&self) -> Duration {
        self.auto_lock_timeout
    }

    /* ------------------- Helpers ----------------------------------------- */

    /// Acquires the vault-data mutex. Always call before [`lock_key`] to
    /// maintain the canonical acquisition order.
    fn lock_data(&self) -> Result<MutexGuard<'_, Option<VaultData>>, VaultError> {
        self.vault_data.lock().map_err(|_| VaultError::VaultLocked)
    }

    /// Acquires the master-key mutex. Always call after [`lock_data`] to
    /// maintain the canonical acquisition order.
    fn lock_key(&self) -> Result<MutexGuard<'_, Option<MasterKey>>, VaultError> {
        self.master_key.lock().map_err(|_| VaultError::VaultLocked)
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn vault_path(&self) -> &Path {
        self.storage.path()
    }

    /// Convenience wrapper exposing password strength estimation.
    pub fn estimate_password_strength(password: &str) -> f64 {
        estimate_password_strength(password)
    }
}

impl Drop for VaultManager {
    fn drop(&mut self) {
        self.lock_vault();
    }
}

/* ------------------- Password Validation --------------------------------- */

/// Validates that a candidate master password meets minimum complexity requirements.
///
/// Requirements:
/// - At least 12 characters
/// - At least 3 of: lowercase, uppercase, digit, special character
///
/// This is a defence-in-depth check at the application boundary. The actual
/// security of the vault is determined by Argon2id key stretching.
pub fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.len() < 12 {
        return Err(VaultError::InvalidPassword);
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ');

    let category_count = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();

    if category_count < 3 {
        return Err(VaultError::InvalidPassword);
    }

    Ok(())
}
