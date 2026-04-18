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

//! Tauri-managed application state
//!
//! [`AppState`] is registered with `app.manage()` during setup and made
//! available to every command handler via Tauri's dependency injection.
//!
//! # Directory security
//! On Unix, the vault directory is created with mode `0o700` in a single
//! `DirBuilder` call, avoiding the TOCTOU race that would occur if we created
//! the directory and then called `set_permissions` separately.
//!
//! # Error handling
//! Initialisation errors are returned as `tauri::Error` strings rather than
//! causing a panic, so Tauri can display a user-facing error dialog instead of
//! crashing silently.

use std::sync::Mutex;

use tauri::AppHandle;

use ferreus_core::VaultManager;

const APP_NAME: &str = "FerreusVault";
const VAULT_FILENAME: &str = "vault.sark";

pub struct AppState {
    /// Mutex-protected vault manager.
    ///
    /// All command handlers that need vault access lock this mutex for the
    /// duration of their operation and release it before returning.
    pub vault: Mutex<VaultManager>,
}

impl AppState {
    /// Resolves the vault directory, creates it if absent, and constructs the
    /// initial (locked) vault manager.
    ///
    /// # Errors
    /// Returns a `String` error if the OS cannot provide an app-data directory
    /// or if directory creation fails. The error is surfaced as a Tauri setup
    /// error rather than a panic.
    pub fn new(app: &AppHandle) -> Result<Self, String> {
        let base_path = app
            .path_resolver()
            .app_data_dir()
            .ok_or_else(|| "OS could not resolve the app data directory".to_string())?
            .join(APP_NAME);

        // Create the vault directory with the correct permissions in one step
        // to avoid the TOCTOU race between `create_dir_all` and `set_permissions`.
        create_vault_dir(&base_path)?;

        let vault_path = base_path.join(VAULT_FILENAME);
        let vault_manager = VaultManager::new(&vault_path);

        Ok(Self {
            vault: Mutex::new(vault_manager),
        })
    }
}

/* ------------------- Directory creation ---------------------------------- */

/// Creates `path` as a directory if it does not already exist.
///
/// On Unix, the directory is created with mode `0o700` atomically, avoiding
/// the TOCTOU race that a separate `chmod` call would introduce.
///
/// On non-Unix platforms, the directory is created with the OS default
/// permissions. If stronger isolation is required on Windows, use an ACL.
fn create_vault_dir(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;

        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
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
