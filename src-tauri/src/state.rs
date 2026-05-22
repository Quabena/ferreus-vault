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

//! Tauri-managed application state.
//!
//! [`AppState`] is registered once with `app.manage()` during setup and is
//! subsequently injected into every command handler that declares a
//! `State<AppState>` parameter.
//!
//! # Vault path resolution
//! The vault file is placed in the OS-provided app data directory:
//!
//! | Platform | Path                                                    |
//! |----------|---------------------------------------------------------|
//! | Linux    | `$XDG_DATA_HOME/FerreusVault/vault.sark`                |
//! | macOS    | `~/Library/Application Support/FerreusVault/vault.sark` |
//! | Windows  | `%APPDATA%\FerreusVault\vault.sark`                     |
//!
//! # Directory security
//! On Unix, the vault directory is created with mode `0o700` (owner-only
//! read/write/execute) in a single `DirBuilder` call, avoiding the TOCTOU
//! race that would occur if directory creation and permission-setting were two
//! separate operations.
//!
//! On non-Unix platforms the directory is created with OS default permissions.
//! For stronger isolation on Windows, apply a restrictive ACL after creation.
//!
//! # Error handling
//! Initialisation errors are returned as `String` and propagated as Tauri
//! setup errors, allowing Tauri to display a user-facing error dialog rather
//! than crashing silently with a panic.

use std::sync::Mutex;

use tauri::AppHandle;

use ferreus_vault::VaultManager;

/// Application-display name, used as the vault subdirectory name inside the
/// OS app-data directory.
const APP_NAME: &str = "FerreusVault";

/// File name of the encrypted vault file.
const VAULT_FILENAME: &str = "vault.sark";

/// Tauri-managed application state, available to all command handlers.
pub struct AppState {
    /// Mutex-protected [`VaultManager`].
    ///
    /// Command handlers lock this mutex for the duration of their operation
    /// and release it before returning. No handler may hold this lock while
    /// performing a blocking I/O call or waiting on another lock (deadlock
    /// prevention).
    ///
    /// The mutex starts in the locked (poisoned-free) state; it is poisoned
    /// only if a command handler panics while holding it, which should never
    /// occur in normal operation.
    pub vault: Mutex<VaultManager>,
}

impl AppState {
    /// Resolves the vault directory, creates it with secure permissions if
    /// absent, and constructs an initial **locked** [`VaultManager`].

    pub fn new(app: &AppHandle) -> Result<Self, String> {
        // Resolve the platform-specific app data directory.
        // `path_resolver().app_data_dir()` returns `None` on platforms where
        // no suitable directory exists — treat this as a fatal setup error.
        let base_path = app
            .path_resolver()
            .app_data_dir()
            .ok_or_else(|| "OS could not resolve the app data directory".to_string())?
            .join(APP_NAME);

        // Create the vault directory with correct permissions atomically.
        // This is done before constructing the VaultManager so that any
        // permission or I/O error surfaces here, not buried inside the manager.
        create_vault_dir(&base_path)?;

        let vault_path = base_path.join(VAULT_FILENAME);

        // VaultManager::new does not open or create the vault file; it only
        // stores the path. The vault remains locked until the user calls
        // `create_vault` or `unlock_vault` via a command handler.
        let vault_manager = VaultManager::new(&vault_path);

        Ok(Self {
            vault: Mutex::new(vault_manager),
        })
    }
}

/* ─────────────────────────── Directory Creation ───────────────────────── */

/// Creates `path` as a directory with secure permissions.
///
/// On Unix, the directory is created with mode `0o700` (owner read/write/
/// execute; no group or other access) in a single atomic `DirBuilder` call.
/// Using `DirBuilder` with `.recursive(true)` and `.mode()` set before
/// `.create()` is called avoids the TOCTOU race that a separate `chmod` would
/// introduce: the permissions are applied at the kernel level on first
/// creation.
///
/// On non-Unix platforms, the standard `create_dir_all` is used. If tighter
/// isolation is required on Windows (e.g. denying access to the SYSTEM
/// account), apply an ACL via the `windows-acl` crate or equivalent.
///
/// Calling this function on an already-existing directory is a no-op on both
/// paths (`recursive(true)` / `create_dir_all` both succeed if the directory
/// already exists).
fn create_vault_dir(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        DirBuilder::new()
            .recursive(true)
            .mode(0o700) // owner rwx only; no group or other
            .create(path)
            .map_err(|e| format!("Failed to create vault directory '{}': {e}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create vault directory '{}': {e}", path.display()))?;
    }

    Ok(())
}
