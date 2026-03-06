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
use serde::Serialize;
use tauri::State;
use zeroize::Zeroizing;

use crate::state::AppState;

use ferreus_core::errors::VaultError;
use ferreus_core::validate_master_password;

#[derive(Serialize)]
pub struct VaultStatus {
    pub unlocked: bool,
    pub vault_exists: bool,
}

/* ------------------------ Create Vault ---------------------- */
#[tauri::command]
pub fn create_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    // Enforce password validation at GUI boundary
    validate_master_password(&password).map_err(sanitize_error)?;

    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault.create_vault(&password).map_err(sanitize_error)
}

/* ---------------------------- Unlock vault -------------------------- */
#[tauri::command]
pub fn unlock_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let password = Zeroizing::new(password);

    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault
        .unlock_vault(&password)
        .map_err(|_| "Invalid password or corrupted vault".to_string())
}

/* ----------------------- Lock Vault ------------------------- */
#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    vault.lock_vault();
    Ok(())
}

#[tauri::command]
pub fn vault_status(state: State<AppState>) -> Result<VaultStatus, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    Ok(VaultStatus {
        unlocked: vault.is_unlocked(),
        vault_exists: state.vault_path.exists(),
    })
}

/* --------------------- Error sanitization -------------------- */
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        _ => "Operation failed".to_string(),
    }
}
