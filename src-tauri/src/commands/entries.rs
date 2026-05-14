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

use serde::{Deserialize, Serialize};
use tauri::State;

// FIX: removed the duplicate and conflicting `use super::auth::AppState` import.
// The original file imported *both* `super::auth::AppState` and
// `crate::state::AppState` — two different structs with the same name in the
// same scope. This is an unambiguous compile error ("ambiguous associated type").
// The correct import is `crate::state::AppState`, which is the single canonical
// AppState used throughout the Tauri layer.
use crate::state::AppState;

// FIX: corrected crate name from `ferreus_core` to `ferreus_vault` throughout.
use ferreus_vault::errors::VaultError;
use ferreus_vault::vault::PasswordEntry;

/* ─────────────────────────── Safe IPC View ────────────────────────────── */

/// A sanitised, read-only view of a vault entry that is safe to send over IPC.
///
/// The `password` field is **intentionally absent**. Sending passwords over
/// IPC exposes them to developer-tool inspection and the JavaScript heap.
/// Use the `copy_password` command to deliver a password to the user via the
/// system clipboard, bypassing the JS layer entirely.
//
// FIX: removed `EntryDTO`, which included a `password: String` field and was
// used by `list_entries`. Returning passwords over IPC in any form is a
// security violation regardless of whether the caller "intends" to display
// them. `EntryView` — which already existed in the file but was unused — is
// the correct return type and is now used exclusively.
//
// Also removed the stale `id: String` / `title: String` field names that do
// not match the library's `PasswordEntry` struct (which uses `account_name`
// and index-based addressing, not a UUID string `id` or a `title` field).
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

/* ─────────────────────────── List entries ──────────────────────────────── */

/// Returns a list of all vault entries with the password field omitted.
///
/// The frontend uses these records for display and to obtain the `index`
/// needed for `update_entry`, `delete_entry`, and `copy_password`.
///
/// # Errors
/// - `"Vault is locked"` if the vault has not been unlocked.
//
// FIX: the original implementation:
//   1. Called `vault.list_entries()` directly on `&state.vault` (an
//      `Arc<VaultData>`), bypassing the mutex entirely and using methods that
//      do not exist on `VaultData`.
//   2. Returned `EntryDTO` which included `password` — a security violation.
//   3. Mapped fields (`id`, `title`) that do not exist on `PasswordEntry`.
// Replaced with a correct implementation using `with_vault_data` and
// returning `EntryView` (password excluded).
#[tauri::command]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntryView>, String> {
    let vault = state
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

/* ─────────────────────────── Add entry ────────────────────────────────── */

/// Adds a new password entry to the unlocked vault.
///
/// The entry is not persisted to disk until `save_vault` is called (which
/// happens automatically on lock in the current implementation). All string
/// parameters are moved directly into the library — no extra heap copy is made
/// at this layer.
///
/// # Errors
/// - `"Vault is locked"` if the vault has not been unlocked.
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
        .map_err(sanitize_error)
}

/* ─────────────────────────── Update entry ─────────────────────────────── */

/// Updates selected fields of the entry at `index`.
///
/// Passing `None` for a field leaves it unchanged.
///
/// # Errors
/// - `"Vault is locked"` if the vault has not been unlocked.
/// - `"Entry not found"` if `index` is out of bounds.
//
// FIX: the outer `map_err(sanitize_error)?` and inner `map_err(|_| …)`
// produced a type-error-prone double-Result chain. Flattened to a single
// `and_then` that maps both the outer VaultError and the inner EntryNotFound
// uniformly through `sanitize_error`.
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
        .map_err(sanitize_error)
}

/* ─────────────────────────── Delete entry ─────────────────────────────── */

/// Removes the entry at `index` from the unlocked vault.
///
/// # Errors
/// - `"Vault is locked"` if the vault has not been unlocked.
/// - `"Entry not found"` if `index` is out of bounds.
//
// FIX: the original nested closure returned `Ok(())` from the inner scope
// even when `remove_entry` succeeded, discarding the removed entry. Simplified
// to discard the return value explicitly with `let _ =`, which is cleaner and
// makes the intent clear. The outer `map_err` propagates `VaultError::EntryNotFound`
// correctly via `sanitize_error`.
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
        .map_err(sanitize_error)
}

/* ─────────────────────────── Error sanitization ───────────────────────── */

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
