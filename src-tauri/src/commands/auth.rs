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

use std::sync::Arc;
use tauri::State;

use ferreus_core::errors::VaultError;
use ferreus_core::vault::VaultData;

pub struct AppState {
    pub vault: Arc<VaultData>,
}

#[tauri::command]
pub fn unlock_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let vault = &state.vault;

    vault
        .unlock(password.as_bytes())
        .map_err(|e| format!("{:?}", e))?;

    Ok(())
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), String> {
    let vault = &state.vault;
    vault.lock();
    Ok(())
}

#[tauri::command]
pub fn create_vault(password: String, state: State<AppState>) -> Result<(), String> {
    let vault = &state.vault;

    vault
        .initialize(password.as_bytes())
        .map_err(|e| format!("{:?}", e))?;

    Ok(())
}
