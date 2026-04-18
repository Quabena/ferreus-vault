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

//! Entry CRUD command handlers
//!
//! # Password handling
//! Passwords received over IPC are `String` values allocated by Tauri's
//! deserializer. We pass them as `&str` borrows directly to the library so no
//! additional heap copy is made within this layer. The original `String` is
//! dropped at the end of each command function.
//!
//! `get_password` has been intentionally removed from this module. Returning a
//! raw password string over the IPC channel exposes it to developer-tool
//! inspection, IPC logging, and the JavaScript heap. The correct path for
//! surfacing a password to the user is `copy_to_clipboard`, which writes
//! directly to the system clipboard without the value ever reaching JS.

use serde::Serialize;
use tauri::State;

use crate::state::AppState;

use ferreus_core::errors::VaultError;
use ferreus_core::vault::PasswordEntry;

/* ------------------- Safe entry view (password excluded) ----------------- */

/// A sanitized read-only view of a vault entry safe to send over IPC.
///
/// The `password` field is intentionally absent. Use `copy_to_clipboard`
/// to deliver a password to the user without it transiting the JS layer.
#[derive(Serialize)]
pub struct EntryView {
    pub id: usize,
    pub account_name: String,
    pub username: String,
    pub notes: String,
}

/* ------------------- List entries ---------------------------------------- */

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
                .map(|(i, entry)| EntryView {
                    id: i, // was hardcoded to 1 — must be the loop index
                    account_name: entry.account_name.clone(),
                    username: entry.username.clone(),
                    notes: entry.notes.clone(),
                })
                .collect::<Vec<_>>()
        })
        .map_err(sanitize_error)
}

/* ------------------- Add entry ------------------------------------------- */

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
            // Pass password as &str — PasswordEntry::new accepts a String,
            // so we clone only once here inside the library, not an extra time
            // in this command layer. The IPC-allocated String is dropped when
            // this command returns.
            let entry = PasswordEntry::new(
                account_name,
                username,
                password, // moved, not cloned — no Zeroizing defeat
                notes,
            );
            data.add_entry(entry);
        })
        .map_err(sanitize_error)
}

/* ------------------- Update entry ---------------------------------------- */

#[tauri::command]
pub fn update_entry(
    id: usize,
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
        .with_vault_data(|data| {
            // password is moved directly — no intermediate Zeroizing clone.
            data.update_entry(id, account_name, username, password, notes)
        })
        .map_err(sanitize_error)?
        .map_err(|_| "Invalid entry ID".to_string())
}

/* ------------------- Delete entry ---------------------------------------- */

#[tauri::command]
pub fn delete_entry(id: usize, state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| {
            data.remove_entry(id)
                .map_err(|_| "Invalid entry ID".to_string())?;
            Ok(())
        })
        .map_err(sanitize_error)?
}

/* ------------------- Error sanitization ---------------------------------- */

/// Maps internal `VaultError` variants to safe, user-facing strings.
///
/// Internal error details are intentionally discarded to avoid leaking
/// implementation information over the IPC channel.
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        _ => "Operation failed".to_string(),
    }
}
