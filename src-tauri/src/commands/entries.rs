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

use std::str;

use serde::Serialize;
use tauri::{App, State};
use zeroize::Zeroizing;

use crate::state::{self, AppState};

use ferreus_core::errors::VaultError;

/* ------------------- Safe Entry View (No Password) ---------------------- */
#[derive(Serialize)]
pub struct EntryView {
    pub id: usize,
    pub account_name: String,
    pub username: String,
    pub notes: String,
}

/* --------------------- List entries -------------------------- */
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
                    id: 1,
                    account_name: entry.account_name.clone(),
                    username: entry.username.clone(),
                    notes: entry.notes.clone(),
                })
                .collect::<Vec<_>>()
        })
        .map_err(sanitize_error)
}

/* ----------------------- Add Entry ----------------------------- */
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

    let password = Zeroizing::new(password);

    vault
        .with_vault_data(|data| {
            let entry = ferreus_core::vault::PasswordEntry::new(
                account_name,
                username,
                password.to_string(),
                notes,
            );
            data.add_entry(entry);
        })
        .map_err(sanitize_error)
}

/* ------------------------------- Update Entry ---------------------------------- */
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

    let password = password.map(Zeroizing::new);

    vault
        .with_vault_data(|data| {
            data.update_entry(
                id,
                account_name,
                username,
                password.map(|p| p.to_string()),
                notes,
            )
        })
        .map_err(sanitize_error)?
        .map_err(|_| "Invalid entry ID".to_string())
}

/* --------------------------- Delete Entry ---------------------------- */
#[tauri::command]
pub fn delete_entry(id: usize, state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .with_vault_data(|data| {
            if id >= data.entries.len() {
                return Err(());
            }
            data.entries.remove(id);
            Ok(())
        })
        .map_err(sanitize_error)?
        .map_err(|_| "Invalid entry ID".to_string())
}

/* -------------------------- Explicit Password Retrieval ----------------------------- */
#[tauri::command]
pub fn get_password(id: usize, state: State<AppState>) -> Result<String, String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Invalid state error".to_string())?;

    vault
        .with_vault_data(|data| data.get_entry(id).map(|e| e.password.clone()))
        .map_err(sanitize_error)?
        .ok_or_else(|| "Invalid entry ID".to_string())
}

/* --------------------- Error Sanitization --------------------- */
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        _ => "Operation failed".to_string(),
    }
}
