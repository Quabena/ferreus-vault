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

//! Entry CRUD command handlers.
//!
//! # Password handling
//! Passwords received over IPC are `String` values allocated by Tauri's
//! deserializer. They are moved directly into the library without extra cloning
//! within this command layer. The `String` is dropped at the end of each
//! command function.
//!
//! # Why `get_password` is absent
//! Returning a raw password string over the IPC channel would expose it to
//! developer-tool inspection, IPC logging, and the JavaScript heap. The correct
//! path is `copy_password` in the clipboard module, which writes directly to
//! the system clipboard without the value ever reaching JavaScript.
//!
//! # Safe IPC surface
//! `list_entries` returns [`EntryView`] values, which deliberately omit the
//! `password` field. The frontend never receives a raw password over IPC.

use serde::Serialize;
use tauri::State;

use crate::state::AppState;

use ferreus_vault::errors::VaultError;
use ferreus_vault::vault::PasswordEntry;

#[derive(Serialize)]
pub struct EntryView {
    /// Zero-based index used to address this entry in update/delete/copy operations.
    pub index: usize,
    /// Human-readable account or service name (e.g., "Gmail").
    pub account_name: String,
    /// Login username or email address.
    pub username: String,
    /// Optional free-text notes.
    pub notes: String,
    // `password` is deliberately absent — use `copy_password` instead.
}

/// Returns a list of all vault entries with the password field omitted.
///
/// The frontend uses these records for display and to obtain the `index`
/// needed for `update_entry`, `delete_entry`, and `copy_password`.
#[tauri::command]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntryView>, String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| {
            data.entries
                .iter()
                .enumerate()
                .map(|(index, e)| EntryView {
                    index,
                    account_name: e.account_name.clone(),
                    username: e.username.clone(),
                    notes: e.notes.clone(),
                    // password deliberately excluded
                })
                .collect::<Vec<_>>()
        })
        .map_err(sanitize_error)
}

/// Adds a new password entry to the unlocked vault.
///
/// The entry is persisted before this command returns, so locking or closing
/// the app immediately after adding an entry does not discard it. All string
/// parameters are moved directly into the library — no extra heap copy is made
/// at this layer.
#[tauri::command]
pub fn add_entry(
    account_name: String,
    username: String,
    password: String,
    notes: String,
    state: State<AppState>,
) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| {
            // All four Strings are moved directly into PasswordEntry::new —
            // no intermediate clone is made at the command layer.
            let entry = PasswordEntry::new(account_name, username, password, notes);
            data.add_entry(entry);
        })
        .map_err(sanitize_error)?;

    vault.save_vault().map_err(sanitize_error)
}

/// Updates selected fields of the entry at `index`.
///
/// Passing `None` for a field leaves it unchanged.
#[tauri::command]
pub fn update_entry(
    index: usize,
    account_name: Option<String>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    state: State<AppState>,
) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| data.update_entry(index, account_name, username, password, notes))
        // Outer VaultError (e.g. VaultLocked) → sanitized string.
        .map_err(sanitize_error)?
        // Inner VaultError from update_entry (e.g. EntryNotFound) → sanitized string.
        .map_err(sanitize_error)?;

    vault.save_vault().map_err(sanitize_error)
}

/// Removes the entry at `index` from the unlocked vault.
#[tauri::command]
pub fn delete_entry(index: usize, state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| {
            // `remove_entry` returns the removed entry; we discard it.
            // The caller does not need the entry contents.
            data.remove_entry(index)
        })
        // Outer VaultError (e.g. VaultLocked).
        .map_err(sanitize_error)?
        // Inner VaultError from remove_entry (e.g. EntryNotFound).
        .map(|_removed| ()) // discard the returned PasswordEntry
        .map_err(sanitize_error)?;

    vault.save_vault().map_err(sanitize_error)
}

/// Maps internal [`VaultError`] variants to safe, user-facing strings.
///
/// Internal error details are intentionally discarded to avoid leaking
/// implementation information over the IPC channel. `Debug` output (`{:?}`)
/// is never forwarded.
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        VaultError::EntryNotFound => "Entry not found".to_string(),
        _ => "Operation failed".to_string(),
    }
}
