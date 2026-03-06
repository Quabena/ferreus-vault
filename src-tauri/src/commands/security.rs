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

use std::fmt::format;
use std::time::Duration;

use tauri::{AppHandle, Manager, State};

use crate::clipboard::{self, ClipboardState};
use crate::state::{self, AppState};

/* ---------------------------- Auto-Lock Policy Bounds ---------------------- */
const MIN_TIMEOUT_SECS: u64 = 10;
const MAX_TIMEOUT_SECS: u64 = 900; // 15 MINUTES
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/* ------------------------------ Set Auto-Lock Timeout ----------------------- */
#[tauri::command]
pub fn set_auto_lock_timeout(
    seconds: u64,
    state: State<AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Enforce bounds
    if seconds < MIN_TIMEOUT_SECS || seconds > MAX_TIMEOUT_SECS {
        return Err(format!(
            "Timeout must be between {} and {} seconds",
            MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS
        ));
    }

    let mut vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    drop(vault); // release lock ASAP

    // Also update clipboard timeout
    if let Some(clipboard) = app.try_state::<ClipboardState>() {
        clipboard.set_timeout(Duration::from_secs(seconds.min(60)));
        // Clipboard timeout capped to 60 seconds max regardless of vault timeout
    }

    Ok(())
}

/* ------------------------------ Get Auto-Lock Timeout ---------------------- */
#[tauri::command]
pub fn get_auto_lock_timeout(state: State<AppState>) -> Result<u64, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    Ok(vault
        .auto_lock_timeout()
        .unwrap_or(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .as_secs())
}
