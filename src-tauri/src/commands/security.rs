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

//! Security policy command handlers.
//!
//! Manages runtime security policies exposed to the frontend:
//! - **Auto-lock timeout**: the inactivity duration after which the vault is
//!   locked automatically by the watchdog thread.
//! - **Clipboard clear timeout**: the duration after which a password copied
//!   to the clipboard is erased. Capped at [`MAX_CLIPBOARD_TIMEOUT_SECS`] and
//!   always ≤ the vault timeout, so clipboard content is cleared at least as
//!   quickly as the vault locks.
//!
//! Both values are validated against hard bounds before being applied.
//! The frontend cannot configure insecure values (e.g., a 24-hour auto-lock
//! or a 10-minute clipboard retention).

use std::time::Duration;

use tauri::{AppHandle, Manager, State};

use crate::clipboard::ClipboardState;
use crate::state::AppState;

/* ─────────────────────────── Policy bounds ────────────────────────────── */

/// Minimum permitted auto-lock timeout (10 seconds).
///
/// Values below this would lock the vault during normal typing, creating a
/// poor user experience without meaningful additional security.
const MIN_TIMEOUT_SECS: u64 = 10;

/// Maximum permitted auto-lock timeout (15 minutes = 900 seconds).
///
/// Values above this leave the vault open for an unreasonably long period
/// on an unattended device. Administrators who need longer timeouts should
/// modify this constant, not expose it as a user-configurable value.
const MAX_TIMEOUT_SECS: u64 = 900;

/// Maximum permitted clipboard clear timeout (60 seconds).
///
/// Capped independently of the vault timeout so that clipboard content is
/// always cleared within 60 seconds, regardless of how long the vault
/// itself stays unlocked. Passwords on the clipboard are higher-risk than an
/// open vault because other applications can read the clipboard at any time.
const MAX_CLIPBOARD_TIMEOUT_SECS: u64 = 60;

/* ─────────────────────────── set_auto_lock_timeout ────────────────────── */

/// Sets the vault inactivity timeout and the clipboard clear timeout.
///
/// `seconds` must be between [`MIN_TIMEOUT_SECS`] and [`MAX_TIMEOUT_SECS`]
/// (inclusive). Values outside this range are rejected with a descriptive
/// error before any state is mutated.
///
/// The clipboard timeout is derived as `min(seconds, MAX_CLIPBOARD_TIMEOUT_SECS)`
/// so it is always ≤ both the vault timeout and the cap.
///
/// # Mutex discipline
/// The vault mutex is released **before** the clipboard timeout is updated, so
/// there is no risk of holding two locks simultaneously.
///
/// # Errors
/// Returns a validation error string if `seconds` is out of range, or
/// `"Internal state error"` if the vault mutex is poisoned (should not occur
/// in normal operation).
#[tauri::command]
pub fn set_auto_lock_timeout(
    seconds: u64,
    state: State<AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // Validate BEFORE acquiring any lock so a bad input never touches state.
    if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&seconds) {
        return Err(format!(
            "Timeout must be between {} and {} seconds",
            MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS
        ));
    }

    // ── Update vault timeout ───────────────────────────────────────────────
    {
        let mut vault = state
            .vault
            .lock()
            .map_err(|_| "Internal state error".to_string())?;

        vault.set_auto_lock_timeout(Duration::from_secs(seconds));
    } // Vault mutex released here, before clipboard state is touched.

    // ── Update clipboard timeout ───────────────────────────────────────────
    // `try_state` returns `None` only if ClipboardState was not registered
    // during setup. In production this should never happen; the `if let`
    // degrades gracefully rather than returning an error, since the vault
    // timeout was already successfully applied.
    if let Some(clipboard) = app.try_state::<ClipboardState>() {
        clipboard.set_timeout(Duration::from_secs(
            seconds.min(MAX_CLIPBOARD_TIMEOUT_SECS),
        ));
    }

    Ok(())
}

/* ─────────────────────────── get_auto_lock_timeout ────────────────────── */

/// Returns the current vault inactivity timeout in seconds.
///
/// Used by the frontend to display and pre-populate the security settings UI.
///
/// # Errors
/// Returns `"Internal state error"` if the vault mutex is poisoned.
#[tauri::command]
pub fn get_auto_lock_timeout(state: State<AppState>) -> Result<u64, String> {
    let vault = state
        .vault
        .lock()
        .map_err(|_| "Internal state error".to_string())?;

    Ok(vault.auto_lock_timeout().as_secs())
}
