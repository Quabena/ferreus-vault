// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferreus Vault Contributors

//! Runtime vault manager
//!
//! This module owns the in-memory decrypted vault state and enforces:
//! - Secure lifecycle of sensitive material
//! - Strict concurrency discipline (deadlock prevention)
//! - Brute-force resistance policies
//!
//! # Security Model
//! - Vault data and keys are never exposed outside controlled closures
//! - Master key is split in memory to reduce exposure surface
//! - All sensitive memory is dropped and zeroized on lock
//!
//! # Mutex Discipline (CRITICAL)
//! ALWAYS acquire locks in this order:
//!     1. vault_data
//!     2. master_key
//!
//! Violating this WILL introduce deadlocks.

pub mod crypto;
pub mod device_key;
pub mod device_store;
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

use crate::crypto::{estimate_password_strength, EncryptedVault, MasterKey, SplitKey};
use crate::errors::VaultError;
use crate::storage::VaultStorage;
use crate::vault::VaultData;

/* ------------------- Vault Manager --------------------------------------- */

pub struct VaultManager {
    /// Decrypted vault contents (None when locked)
    vault_data: Arc<Mutex<Option<VaultData>>>,

    /// Split master key stored in memory (None when locked)
    master_key: Arc<Mutex<Option<SplitKey>>>,

    storage: VaultStorage,

    auto_lock_timeout: Duration,
    last_activity: Instant,

    failed_attempts: u32,
    lockout_until: Option<Instant>,

    /// Unique runtime session ID (for audit logging)
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

    pub fn create_vault(&self, password: &str) -> Result<(), VaultError> {
        if self.storage.vault_exists() {
            return Err(VaultError::CryptoError("Vault already exists".into()));
        }

        let vault_data = VaultData::new();
        self.storage.create_vault(password, &vault_data)
    }

    /* ------------------- Unlocking --------------------------------------- */

    pub fn unlock_vault(&mut self, password: &str) -> Result<(), VaultError> {
        let now = Instant::now();

        // Hard lockout check
        if let Some(until) = self.lockout_until {
            if now < until {
                return Err(VaultError::InvalidPassword);
            }
            self.lockout_until = None;
        }

        // Timing jitter (anti-enumeration)
        let jitter = rand::thread_rng().gen_range(100..800);
        std::thread::sleep(Duration::from_millis(jitter));

        match self.try_unlock(password) {
            Ok(_) => {
                self.failed_attempts = 0;
                Ok(())
            }
            Err(e) => {
                self.failed_attempts += 1;

                // Exponential backoff
                let delay = 2u64
                    .saturating_pow(self.failed_attempts.saturating_sub(1))
                    .min(15);

                std::thread::sleep(Duration::from_secs(delay));

                if self.failed_attempts >= 5 {
                    self.lockout_until = Some(Instant::now() + Duration::from_secs(30));
                }

                Err(e)
            }
        }
    }

    fn try_unlock(&mut self, password: &str) -> Result<(), VaultError> {
        let (vault_data, master_key) = self.storage.load_vault(password)?;

        {
            // 🔐 limit borrow scope
            let mut data_lock = self.lock_data()?;
            let mut key_lock = self.lock_key()?;

            *data_lock = Some(vault_data);

            let key_bytes = *master_key.key_bytes();
            *key_lock = Some(SplitKey::new(key_bytes));
        }

        self.touch();

        Ok(())
    }
    /* ------------------- Locking ----------------------------------------- */

    pub fn lock_vault(&self) {
        if let Ok(mut data) = self.vault_data.lock() {
            *data = None;
        }

        if let Ok(mut key) = self.master_key.lock() {
            *key = None;
        }

        crate::logging::log_security_event("Vault locked");
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault_data.lock().map(|v| v.is_some()).unwrap_or(false)
    }

    /* ------------------- Persistence ------------------------------------- */

    pub fn save_vault(&mut self) -> Result<(), VaultError> {
        let encrypted_bytes = {
            let data_guard = self.lock_data()?;
            let key_guard = self.lock_key()?;

            match (&*data_guard, &*key_guard) {
                (Some(data), Some(split_key)) => {
                    let serialized =
                        bincode::serialize(data).map_err(|_| VaultError::SerializationError)?;

                    // Reconstruct full key temporarily
                    let key_bytes = split_key.reconstruct();

                    // reconstruct MasterKey WITHOUT salt reuse here.
                    // Storage layer should handle salt persistence.
                    let master_key = MasterKey::from_raw(key_bytes);

                    let encrypted = EncryptedVault::encrypt(&serialized, &master_key)?;
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

    pub fn with_vault_data<F, T>(&mut self, op: F) -> Result<T, VaultError>
    where
        F: FnOnce(&mut VaultData) -> T,
    {
        let result = {
            let mut guard = self.lock_data()?;

            match &mut *guard {
                Some(data) => Ok(op(data)),
                None => Err(VaultError::VaultLocked),
            }
        };

        if result.is_ok() {
            self.touch();
        }

        result
    }

    /* ------------------- Auto-lock --------------------------------------- */

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

    fn lock_data(&self) -> Result<MutexGuard<'_, Option<VaultData>>, VaultError> {
        self.vault_data.lock().map_err(|_| VaultError::VaultLocked)
    }

    fn lock_key(&self) -> Result<MutexGuard<'_, Option<SplitKey>>, VaultError> {
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

/* ------------------- Password Validation -------------------------------- */

pub fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.len() < 12 {
        return Err(VaultError::InvalidPassword);
    }

    let categories = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password
            .chars()
            .any(|c| c.is_ascii_punctuation() || c == ' '),
    ];

    if categories.iter().filter(|&&x| x).count() < 3 {
        return Err(VaultError::InvalidPassword);
    }

    Ok(())
}
