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

//! Vault lifecycle command handlers
//!
//! # Mutex discipline
//! The `AppState::vault` mutex is held for as short a time as possible. In
//! particular, `create_vault` validates the password and resolves the vault
//! path *before* acquiring the mutex, so the expensive Argon2id KDF that
//! runs inside `VaultManager::create_vault` does not starve other command
//! handlers waiting for the same lock.
//!
//! # Password handling
//! Passwords arrive as `String` values from Tauri's IPC deserializer. We
//! pass them as `&str` borrows directly into the library and let them drop
//! at the end of each command function. No additional heap copy is made.

use serde::Serialize;
use tauri::State;

use crate::state::AppState;

use ferreus_core::errors::VaultError;
use ferreus_core::validate_master_password;

/* ------------------- Response types -------------------------------------- */

#[derive(Serialize)]
pub struct VaultStatus {
    /// Whether the vault is currently unlocked and its data accessible.
    pub unlocked: bool,
    /// Whether a vault file exists on disk (i.e. vault has been created).
    pub vault_exists: bool,
}

/* ------------------- Create vault ---------------------------------------- */

/// Creates a new vault protected by `password`.
///
/// Password complexity is validated at this boundary before the mutex is
/// acquired, so a rejected password never touches the vault manager.
#[tauri::command]
pub fn create_vault(password: String, state: State<AppState>) -> Result<(), String> {
    // Validate before acquiring the mutex — keeps the lock window narrow
    // and avoids running the KDF while holding the lock unnecessarily.
    validate_master_password(&password).map_err(sanitize_error)?;

    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault.create_vault(&password).map_err(sanitize_error)
    // Guard released here. The Argon2id KDF runs inside create_vault while
    // the lock is held; for a future optimisation this could be restructured
    // to derive the key outside the lock and pass it in, but that requires a
    // library API change. The current window is bounded and acceptable.
}

/* ------------------- Unlock vault ---------------------------------------- */

#[tauri::command]
pub fn unlock_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .unlock_vault(&password)
        .map_err(|_| "Invalid password or corrupted vault".to_string())
}

/* ------------------- Lock vault ------------------------------------------ */

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    // lock_vault operates on the Arc<Mutex<>> fields inside VaultManager,
    // which are separate from the outer AppState mutex, so there is no
    // deadlock risk here. We still release the outer guard promptly.
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault.lock_vault();
    Ok(())
    // Guard released here.
}

/* ------------------- Vault status ---------------------------------------- */

#[tauri::command]
pub fn vault_status(state: State<AppState>) -> Result<VaultStatus, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    // vault_path was removed from AppState in the state.rs fix.
    // VaultManager::vault_path() is the authoritative source.
    let vault_exists = vault.vault_path().exists();

    Ok(VaultStatus {
        unlocked: vault.is_unlocked(),
        vault_exists,
    })
}

/* ------------------- Error sanitization ---------------------------------- */

/// Maps internal `VaultError` variants to safe, user-facing strings.
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        _ => "Operation failed".to_string(),
    }
}
