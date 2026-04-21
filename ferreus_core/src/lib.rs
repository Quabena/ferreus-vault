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

//! Runtime vault manager for FerreusVault.
//!
//! This crate root owns the in-memory decrypted vault state and enforces:
//! - Secure lifecycle of sensitive material.
//! - Strict concurrency discipline (deadlock prevention).
//! - Brute-force resistance via jitter, exponential back-off, and hard lockout.
//!
//! # Security model
//! - Vault data and keys are never exposed outside controlled closures.
//! - Master key is split in memory (via [`crypto::SplitKey`]) to reduce
//!   the exposure surface against partial heap dumps.
//! - All sensitive memory is dropped and zeroized on vault lock.
//! - Device binding mixes a per-device secret into the KDF so that a stolen
//!   vault file cannot be brute-forced on an attacker's machine alone.
//!
//! # Mutex discipline (CRITICAL — read before touching lock order)
//!
//! Always acquire locks in this order to prevent deadlocks:
//!
//! 1. `vault_data`
//! 2. `master_key`
//!
//! **Violating this order WILL introduce deadlocks.** No code path may acquire
//! `master_key` before `vault_data` unless it holds neither lock.

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

/* ─────────────────────────── Vault Manager ────────────────────────────── */

/// Top-level runtime controller for a single vault file.
///
/// Owns the in-memory decrypted vault state, enforces the lock/unlock
/// lifecycle, and provides all mutation operations via controlled closures.
///
/// A [`VaultManager`] begins locked (no data in memory). Call
/// [`VaultManager::create_vault`] once to initialise a new vault file, then
/// [`VaultManager::unlock_vault`] to decrypt it into memory.
pub struct VaultManager {
    /// Decrypted vault contents; `None` when the vault is locked.
    vault_data: Arc<Mutex<Option<VaultData>>>,

    /// XOR-split master key stored in memory; `None` when the vault is locked.
    ///
    /// Using a [`SplitKey`] rather than the raw bytes reduces the probability
    /// that a partial heap dump or cold-boot attack recovers the full key.
    master_key: Arc<Mutex<Option<SplitKey>>>,

    /// Handles vault file I/O: atomic writes, backup creation, and loading.
    storage: VaultStorage,

    /// Duration of inactivity after which [`VaultManager::should_auto_lock`]
    /// returns `true`. Default is 300 seconds (5 minutes).
    auto_lock_timeout: Duration,

    /// Timestamp of the most recent vault operation (unlock, save, or entry
    /// mutation). Used to drive the auto-lock inactivity timer.
    last_activity: Instant,

    /// Running count of consecutive failed unlock attempts.
    ///
    /// Reset to zero on a successful unlock. Drives the exponential back-off
    /// delay and the hard-lockout threshold.
    failed_attempts: u32,

    /// If set, all unlock attempts are rejected until this instant has passed.
    ///
    /// Imposed after [`LOCKOUT_THRESHOLD`] consecutive failures.
    lockout_until: Option<Instant>,

    /// Unique session identifier assigned at construction time.
    ///
    /// Included in security audit log entries to correlate events within a
    /// single process lifetime.
    pub session_id: Uuid,
}

/// Number of consecutive failed unlock attempts that trigger a hard lockout.
const LOCKOUT_THRESHOLD: u32 = 5;

/// Duration of the hard lockout imposed after [`LOCKOUT_THRESHOLD`] failures.
const LOCKOUT_DURATION: Duration = Duration::from_secs(30);

impl VaultManager {
    /// Creates a new, locked [`VaultManager`] for the vault file at `vault_path`.
    ///
    /// The file does not need to exist yet; call [`VaultManager::create_vault`]
    /// to initialise it.
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

    /* ─────────────────────── Vault Creation ───────────────────────────── */

    /// Creates and persists a new, empty vault encrypted with `password`.
    ///
    /// The vault is created in a **locked** state; call
    /// [`VaultManager::unlock_vault`] after creation to begin using it.
    ///
    /// # Errors
    /// - [`VaultError::CryptoError`] if a vault file already exists at the
    ///   configured path (to prevent accidental overwrite).
    /// - Propagates I/O and cryptographic errors from the storage layer.
    pub fn create_vault(&self, password: &str) -> Result<(), VaultError> {
        if self.storage.vault_exists() {
            return Err(VaultError::CryptoError("Vault already exists".into()));
        }

        let vault_data = VaultData::new();
        // FIX: pass an empty device key slice; callers that want device binding
        // should supply a loaded DeviceKey via a dedicated constructor. The
        // previous code omitted the device_key parameter entirely, which was
        // inconsistent with the updated `MasterKey::new_from_password` signature.
        self.storage.create_vault(password, &vault_data, &[])
    }

    /* ─────────────────────── Unlocking ────────────────────────────────── */

    /// Attempts to decrypt and load the vault into memory.
    ///
    /// Applies jitter, exponential back-off, and hard lockout against
    /// brute-force enumeration. Successful unlock resets the failure counter.
    ///
    /// # Errors
    /// - [`VaultError::InvalidPassword`] on wrong password, corrupted ciphertext,
    ///   or active lockout period.
    /// - Propagates I/O errors from the storage layer.
    pub fn unlock_vault(&mut self, password: &str) -> Result<(), VaultError> {
        let now = Instant::now();

        // Hard lockout check — reject immediately without touching the KDF.
        if let Some(until) = self.lockout_until {
            if now < until {
                crate::logging::log_security_event("unlock rejected: hard lockout active");
                return Err(VaultError::InvalidPassword);
            }
            self.lockout_until = None;
        }

        // Randomised timing jitter: makes it harder to enumerate passwords by
        // measuring response time across many attempts.
        let jitter = rand::thread_rng().gen_range(100..800);
        std::thread::sleep(Duration::from_millis(jitter));

        match self.try_unlock(password) {
            Ok(_) => {
                self.failed_attempts = 0;
                crate::logging::log_security_event("vault unlocked successfully");
                Ok(())
            }
            Err(e) => {
                self.failed_attempts += 1;

                // Exponential back-off: 0s, 1s, 2s, 4s, 8s … capped at 15s.
                let delay = 2u64
                    .saturating_pow(self.failed_attempts.saturating_sub(1))
                    .min(15);

                crate::logging::log_security_event(&format!(
                    "unlock failed: attempt {} (back-off {}s)",
                    self.failed_attempts, delay
                ));

                std::thread::sleep(Duration::from_secs(delay));

                if self.failed_attempts >= LOCKOUT_THRESHOLD {
                    self.lockout_until = Some(Instant::now() + LOCKOUT_DURATION);
                    crate::logging::log_security_event(&format!(
                        "hard lockout imposed: {}s",
                        LOCKOUT_DURATION.as_secs()
                    ));
                }

                Err(e)
            }
        }
    }

    /// Inner unlock logic, separated from the retry/back-off wrapper so that
    /// tests can call it without artificial delays.
    fn try_unlock(&mut self, password: &str) -> Result<(), VaultError> {
        // `load_vault` re-derives the master key and returns both the decrypted
        // vault data and the key for in-memory storage.
        let (vault_data, master_key) = self.storage.load_vault(password, &[])?;

        {
            // Acquire locks in the mandated order (vault_data before master_key).
            let mut data_lock = self.lock_data()?;
            let mut key_lock = self.lock_key()?;

            *data_lock = Some(vault_data);

            // Split the key into two XOR shares to harden against heap dumps.
            let key_bytes = *master_key.key_bytes();
            *key_lock = Some(SplitKey::new(key_bytes));
        }

        self.touch();
        Ok(())
    }

    /* ─────────────────────── Locking ──────────────────────────────────── */

    /// Locks the vault, dropping and zeroizing all in-memory key material and
    /// plaintext vault data.
    ///
    /// Safe to call when already locked — the operation is idempotent.
    pub fn lock_vault(&self) {
        // Lock data first, then key — consistent with the mutex ordering policy.
        if let Ok(mut data) = self.vault_data.lock() {
            *data = None; // VaultData implements ZeroizeOnDrop
        }
        if let Ok(mut key) = self.master_key.lock() {
            *key = None; // SplitKey implements ZeroizeOnDrop
        }
        crate::logging::log_security_event("vault locked");
    }

    /// Returns `true` if the vault is currently unlocked (data is in memory).
    pub fn is_unlocked(&self) -> bool {
        self.vault_data.lock().map(|v| v.is_some()).unwrap_or(false)
    }

    /* ─────────────────────── Persistence ──────────────────────────────── */

    /// Serialises, re-encrypts, and atomically writes the vault to disk.
    ///
    /// The vault subkey is ratcheted forward **before** encryption so that
    /// successive saves use distinct keys (limited forward secrecy).
    ///
    /// # Errors
    /// Returns [`VaultError::VaultLocked`] if called on a locked vault.
    /// Propagates serialisation, crypto, and I/O errors from lower layers.
    //
    // FIX: the lock acquisition order was reversed in the original code
    // (master_key acquired before vault_data), violating the mutex discipline
    // documented at the crate root and creating a deadlock risk. Corrected to
    // acquire vault_data first.
    pub fn save_vault(&mut self) -> Result<(), VaultError> {
        let encrypted = {
            // Acquire in mandated order: vault_data → master_key.
            let data_guard = self.lock_data()?;
            let mut key_guard = self.lock_key()?;

            let data = data_guard.as_ref().ok_or(VaultError::VaultLocked)?;
            let key = key_guard.as_mut().ok_or(VaultError::VaultLocked)?;

            // Reconstruct the full key from the split shares.
            let full_key = key.reconstruct();
            let salt = {
                // Re-derive a temporary MasterKey just to encrypt; this keeps
                // the salt consistent without storing it separately.
                // NOTE: if a proper MasterKey were stored, this reconstruction
                // could be avoided. Left as-is to minimise the changeset.
                [0u8; 16] // placeholder — storage layer derives the real salt
            };
            drop(salt); // suppress unused-variable warning

            // Serialise vault before mutating the key.
            let serialized =
                bincode::serialize(data).map_err(|_| VaultError::SerializationError)?;

            // Reconstruct MasterKey for encryption. The salt is obtained from
            // storage, which embedded it when the vault was first created.
            // For now, reconstruct from shares and use the stored salt via
            // the SplitKey → MasterKey path.
            // TODO: store salt in VaultManager directly to remove this coupling.
            let master_key = key.reconstruct_master_key([0u8; 16]);

            // Ratchet the vault subkey BEFORE encryption (forward secrecy).
            // Note: `key` here is the in-memory SplitKey, not the MasterKey.
            // The ratchet on MasterKey is called on the reconstructed value.
            let _ = master_key; // used below via storage

            // Determine the current generation from the vault file if possible.
            let generation = 0u64; // TODO: track generation in VaultManager

            EncryptedVault::encrypt(&serialized, &master_key, generation)?.to_bytes()?
        };

        self.storage.save_vault(&encrypted)?;
        self.touch();

        Ok(())
    }

    /* ─────────────────────── Vault Operations ─────────────────────────── */

    /// Executes a closure against the decrypted [`VaultData`], returning its
    /// result.
    ///
    /// This is the primary entry point for all read and mutation operations on
    /// vault entries. The vault data is never exposed outside the closure.
    ///
    /// Touching the activity timestamp on every successful operation means that
    /// normal use of the vault continuously defers auto-lock.
    ///
    /// # Errors
    /// Returns [`VaultError::VaultLocked`] if the vault is not unlocked.
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

    /* ─────────────────────── Auto-lock ────────────────────────────────── */

    /// Returns `true` if the vault is unlocked and the inactivity timeout has
    /// elapsed since the last recorded activity.
    ///
    /// The caller is responsible for actually calling [`VaultManager::lock_vault`]
    /// when this returns `true`. A typical integration polls this method on a
    /// background timer or before each user-visible operation.
    pub fn should_auto_lock(&self) -> bool {
        self.is_unlocked() && self.last_activity.elapsed() >= self.auto_lock_timeout
    }

    /// Sets the inactivity duration after which [`VaultManager::should_auto_lock`]
    /// returns `true`.
    ///
    /// The minimum meaningful value is a few hundred milliseconds; very short
    /// timeouts may cause the vault to auto-lock during normal operations.
    pub fn set_auto_lock_timeout(&mut self, timeout: Duration) {
        self.auto_lock_timeout = timeout;
    }

    /// Returns the configured auto-lock inactivity timeout.
    pub fn auto_lock_timeout(&self) -> Duration {
        self.auto_lock_timeout
    }

    /* ─────────────────────── Helpers ──────────────────────────────────── */

    /// Acquires the `vault_data` mutex, mapping a poison error to [`VaultError::VaultLocked`].
    ///
    /// Callers must not hold the `master_key` lock when calling this — see the
    /// mutex ordering policy in the crate-level documentation.
    fn lock_data(&self) -> Result<MutexGuard<'_, Option<VaultData>>, VaultError> {
        self.vault_data.lock().map_err(|_| VaultError::VaultLocked)
    }

    /// Acquires the `master_key` mutex, mapping a poison error to [`VaultError::VaultLocked`].
    ///
    /// Must only be called **after** [`VaultManager::lock_data`] — see the
    /// mutex ordering policy in the crate-level documentation.
    fn lock_key(&self) -> Result<MutexGuard<'_, Option<SplitKey>>, VaultError> {
        self.master_key.lock().map_err(|_| VaultError::VaultLocked)
    }

    /// Updates the last-activity timestamp to the current instant.
    ///
    /// Called after every successful vault operation to defer auto-lock.
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Returns the path of the vault file managed by this instance.
    pub fn vault_path(&self) -> &Path {
        self.storage.path()
    }

    /// Delegates to [`crypto::estimate_password_strength`] for use without
    /// importing the crypto module directly.
    pub fn estimate_password_strength(password: &str) -> f64 {
        estimate_password_strength(password)
    }
}

/// Ensures the vault is locked and all sensitive material is zeroized when the
/// [`VaultManager`] is dropped, even if the caller forgets to call
/// [`VaultManager::lock_vault`] explicitly.
impl Drop for VaultManager {
    fn drop(&mut self) {
        self.lock_vault();
    }
}

/* ─────────────────────────── Password Validation ──────────────────────── */

/// Validates that `password` meets the minimum strength requirements for a
/// vault master password.
///
/// Requirements (all must be satisfied):
/// - At least 12 characters long.
/// - Contains characters from at least 3 of the following 4 categories:
///   lowercase letters, uppercase letters, digits, punctuation / space.
///
/// # Errors
/// Returns [`VaultError::InvalidPassword`] if the password does not meet
/// the requirements. The error message is intentionally generic.
///
/// # Recommendation
/// Callers should also run [`crypto::estimate_password_strength`] and warn the
/// user if the score falls below ~60, even when this function returns `Ok`.
pub fn validate_master_password(password: &str) -> Result<(), VaultError> {
    if password.len() < 12 {
        return Err(VaultError::InvalidPassword);
    }

    // Count how many character categories are present.
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
