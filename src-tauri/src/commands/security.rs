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

//! Security policy command handlers
//!
//! Manages runtime security policies: auto-lock timeout and clipboard
//! clear timeout. Both are validated against hard bounds before being
//! applied to ensure the user cannot configure insecure values.

use std::time::Duration;

use tauri::{AppHandle, Manager, State};

use crate::clipboard::ClipboardState;
use crate::state::AppState;

/* ------------------- Policy bounds --------------------------------------- */

/// Minimum permitted auto-lock timeout in seconds (10 s).
const MIN_TIMEOUT_SECS: u64 = 10;
/// Maximum permitted auto-lock timeout in seconds (15 minutes).
const MAX_TIMEOUT_SECS: u64 = 900;
/// Maximum permitted clipboard clear timeout in seconds.
/// Capped independently of the vault timeout so sensitive content
/// on the clipboard is cleared sooner than the vault locks.
const MAX_CLIPBOARD_TIMEOUT_SECS: u64 = 60;

/* ------------------- Set auto-lock timeout ------------------------------- */

/// Updates the vault inactivity timeout and the clipboard clear timeout.
///
/// `seconds` must be between [`MIN_TIMEOUT_SECS`] and [`MAX_TIMEOUT_SECS`]
/// (inclusive). The clipboard timeout is capped independently at
/// [`MAX_CLIPBOARD_TIMEOUT_SECS`] so that clipboard content is cleared
/// no later than 60 seconds regardless of the vault timeout.
#[tauri::command]
pub fn set_auto_lock_timeout(
    seconds: u64,
    state: State<AppState>,
    app: AppHandle,
) -> Result<(), String> {
    if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&seconds) {
        return Err(format!(
            "Timeout must be between {} and {} seconds",
            MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS
        ));
    }

    {
        let mut vault = state
            .vault
            .lock()
            .map_err(|_| "Internal state error".to_string())?;

        vault.set_auto_lock_timeout(Duration::from_secs(seconds));
    } // lock dropped here

    if let Some(clipboard) = app.try_state::<ClipboardState>() {
        clipboard.set_timeout(Duration::from_secs(seconds.min(MAX_CLIPBOARD_TIMEOUT_SECS)));
    }

    Ok(())
}

#[tauri::command]
pub fn get_auto_lock_timeout(state: State<AppState>) -> Result<u64, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    Ok(vault.auto_lock_timeout().as_secs())
}
