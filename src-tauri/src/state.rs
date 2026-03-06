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

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{AppHandle, Manager};

use ferreus_core::VaultManager;

const APP_NAME: &str = "FerreusVault";
const VAULT_FILENAME: &str = "vault.dat";

pub struct AppState {
    pub vault: Mutex<VaultManager>,
    pub vault_path: PathBuf,
}

impl AppState {
    pub fn new(app: &AppHandle) -> Self {
        // Resolve OS-Specific app data directory safely
        let mut base_path = app
            .path_resolver()
            .app_data_dir()
            .expect("Failed to resolve app data directory");

        // App-specific folder
        base_path.push(APP_NAME);

        // Create directory if missing
        std::fs::create_dir_all(&base_path).expect("Failed to create vault directory");

        // Enforce restrictive permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&base_path, perms)
                .expect("Failed to set secure directory permissions");
        }

        // Vault file location
        let vault_path = base_path.join(VAULT_FILENAME);

        let vault_manager = VaultManager::new(&vault_path);

        Self {
            vault: Mutex::new(vault_manager),
            vault_path,
        }
    }
}
