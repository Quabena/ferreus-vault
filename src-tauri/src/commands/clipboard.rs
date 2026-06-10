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

//! Clipboard command handlers.
//!
//! # Security note on IPC secrets
//! Tauri deserialises command arguments from a JSON string in the IPC layer.
//! By the time `copy_to_clipboard` receives `content`, the framework has
//! already allocated a plain `String` on the heap. Wrapping that `String` in
//! `Zeroizing` after the fact only zeroes our own copy — the IPC buffer is
//! outside our control.
//!
//! The practical mitigation is to keep the sensitive string alive as briefly
//! as possible: we pass it as `&str` directly to `ClipboardState::copy_secure`
//! (which hashes it without retaining a copy) and let it drop at the end of
//! this function. Do not clone or store it anywhere in this path.
//!
//! # Command surface
//! | Command            | Description                                     |
//! |--------------------|-------------------------------------------------|
//! | `copy_to_clipboard`| General-purpose secure copy with auto-clear.   |
//! | `copy_password`    | Copies an entry's password by index; avoids    |
//! |                    | returning the raw value over IPC to JavaScript. |

use tauri::{AppHandle, Manager, State};

use crate::clipboard::ClipboardState;
use crate::state::AppState;

use ferreus_vault::errors::VaultError;

/// Writes `content` to the system clipboard and schedules an auto-clear.
///
/// The auto-clear fires after the timeout configured in
/// [`ClipboardState`] (default 20 s). If the clipboard content has been
/// replaced by another application before the timer fires, the clear is
/// skipped.
///
/// # Errors
/// Returns a `String` error if the system clipboard is unavailable or if
/// writing fails.
#[tauri::command]
pub fn copy_to_clipboard(content: String, app: AppHandle) -> Result<(), String> {
    let clipboard = app
        .try_state::<ClipboardState>()
        .ok_or_else(|| "Clipboard state not initialised".to_string())?;

    // Pass as `&str` — `copy_secure` hashes the bytes without storing a copy.
    clipboard.copy_secure(&content)
    // `content` is dropped here; its heap allocation is freed (not zeroized,
    // because it arrived from the IPC deserializer and we have no control over
    // prior copies in the IPC buffer).
}

/// Copies the password of the vault entry at `index` to the clipboard.
///
/// The password is retrieved from the in-memory vault and passed directly
/// to `ClipboardState::copy_secure` without it ever being serialised to
/// JSON or returned to the JavaScript layer. This is the only safe way to
/// deliver a password to the user from a Tauri command.
///
/// # Errors
/// - `"Vault is locked"` if the vault has not been unlocked.
/// - `"Entry not found"` if `index` is out of bounds.
/// - Clipboard errors from the underlying `ClipboardState`.
#[tauri::command]
pub fn copy_password(index: usize, state: State<AppState>, app: AppHandle) -> Result<(), String> {
    // Retrieve the password from the vault under the mutex.
    // We copy it out as a plain `String` so the guard is not held during
    // the (potentially blocking) clipboard call.
    let password = {
        let mut vault = state
            .vault
            .lock()
            .map_err(|_| "Internal state error".to_string())?;

        vault
            .with_vault_data(|data| {
                data.get_entry(index)
                    .map(|e| e.password.clone())
                    .ok_or_else(|| "Entry not found".to_string())
            })
            .map_err(|e| sanitize_error(e))?
        // `vault` guard is dropped here, before the clipboard call.
    }?;

    // Delegate to shared clipboard infrastructure.
    let clipboard = app
        .try_state::<ClipboardState>()
        .ok_or_else(|| "Clipboard state not initialised".to_string())?;

    let result = clipboard.copy_secure(&password);

    // `password` is dropped here. Its contents are not zeroized because
    // `String::drop` does not scrub memory. The value lived only for the
    // duration of this function. For future hardening, consider returning
    // `Zeroizing<String>` from `get_entry` in the library layer.
    result
}

/// Maps internal `VaultError` variants to safe, user-facing strings.
///
/// `Debug` output is intentionally not forwarded over IPC — it may contain
/// internal detail that aids an attacker or reveals implementation structure.
fn sanitize_error(err: VaultError) -> String {
    match err {
        VaultError::VaultLocked => "Vault is locked".to_string(),
        VaultError::EntryNotFound => "Entry not found".to_string(),
        _ => "Operation failed".to_string(),
    }
}
