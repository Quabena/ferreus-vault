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

//! Vault lifecycle command handlers.
//!
//! # Mutex discipline
//! The `AppState::vault` mutex is held for as short a time as possible.
//! `create_vault` validates the password **before** acquiring the lock, so a
//! rejected password never touches the vault manager and never delays other
//! command handlers waiting for the same mutex.
//!
//! # Password handling
//! Passwords arrive as `String` values from Tauri's IPC deserializer. They
//! are passed as `&str` borrows into the library and dropped at the end of
//! each command function. No additional heap copy is made at this layer.
//!
//! # Error sanitization
//! All `VaultError` variants are mapped to safe, user-facing strings via
//! [`sanitize_error`] before being returned over IPC. Internal `Debug`
//! output (`{:?}`) is never forwarded — it may contain implementation detail
//! that aids an attacker.

use serde::Serialize;
use tauri::State;

use crate::state::AppState;

use ferreus_vault::errors::VaultError;
use ferreus_vault::validate_master_password;

/// Vault status payload returned by [`vault_status`].
#[derive(Serialize)]
pub struct VaultStatus {
    /// Whether the vault is currently unlocked and its data accessible in memory.
    pub unlocked: bool,
    /// Whether a vault file exists on disk (i.e., the vault has been created).
    pub vault_exists: bool,
}

/// Creates a new vault protected by `password`.
///
/// Password complexity is validated **before** the mutex is acquired, so a
/// rejected password never enters the vault manager and the lock window for
/// the expensive Argon2id KDF is kept as narrow as possible.
///
/// # Errors
/// - `"Operation failed"` if the password fails complexity validation.
/// - `"Operation failed"` if a vault already exists at the configured path.
/// - `"Internal state error"` if the vault mutex is poisoned.
#[tauri::command]
pub fn create_vault(password: String, state: State<AppState>) -> Result<(), String> {
    // Validate complexity BEFORE acquiring the mutex.
    validate_master_password(&password).map_err(sanitize_error)?;

    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault.create_vault(&password).map_err(sanitize_error)
    // Guard released here. The Argon2id KDF runs inside `create_vault` while
    // the lock is held. For a future optimisation, the KDF could be run
    // outside the lock and the derived key passed in, but this requires a
    // library API change. The current window is bounded and acceptable for
    // an operation that runs at most once per device lifetime.
}

/// Decrypts the vault and loads it into memory using `password`.
///
/// On success, the vault is unlocked and entry commands become available.
/// On failure, a generic error is returned — the caller cannot distinguish
/// a wrong password from a corrupted vault file (intentional, to prevent
/// oracle attacks).
///
/// # Errors
/// - `"Invalid password or corrupted vault"` on authentication failure.
/// - `"Internal state error"` if the vault mutex is poisoned.
#[tauri::command]
pub fn unlock_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    // The generic error message is intentional — distinguishing wrong-password
    // from corrupted-vault would assist an oracle attacker.
    vault
        .unlock_vault(&password)
        .map_err(|_| "Invalid password or corrupted vault".to_string())
}

/// Locks the vault, dropping and zeroizing all in-memory key material and
/// decrypted vault data.
///
/// Safe to call when the vault is already locked — the operation is idempotent.
///
/// # Errors
/// - `"Internal state error"` if the outer `AppState` mutex is poisoned.
///
/// # Note on inner vs outer mutex
/// `VaultManager::lock_vault` acquires the inner `vault_data` and `master_key`
/// mutexes internally. The outer `AppState` mutex we acquire here is a
/// different lock — there is no deadlock risk.
#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    if vault.is_unlocked() {
        vault.save_vault().map_err(sanitize_error)?;
    }

    vault.lock_vault();
    Ok(())
    // Outer guard released here; `lock_vault` has already dropped the inner guards.
}

/// Returns the current vault status for the frontend.
///
/// Used on startup and after unlock/lock operations to keep the UI in sync
/// with the backend state.
///
/// # Errors
/// - `"Internal state error"` if the vault mutex is poisoned.
#[tauri::command]
pub fn vault_status(state: State<AppState>) -> Result<VaultStatus, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    let vault_exists = vault.vault_path().exists();

    Ok(VaultStatus {
        unlocked: vault.is_unlocked(),
        vault_exists,
    })
}

/// Maps internal [`VaultError`] variants to safe, generic user-facing strings.
///
/// `Debug` output (`{:?}`) is **never** forwarded over IPC — it may contain
/// algorithm-specific detail (e.g., Argon2 parameters, file paths, internal
/// state) that could assist an attacker or leak implementation details.
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        VaultError::InvalidPassword => "Invalid password".to_string(),
        VaultError::EntryNotFound => "Entry not found".to_string(),
        _ => "Operation failed".to_string(),
    }
}
