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
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Manager};

use crate::clipboard::{self, ClipboardState};
use crate::state::AppState;

/* ---------------------------- Background Auto-Lock Task -------------------- */
pub fn start_auto_lock_task(app: AppHandle) {
    thread::spawn(move || {
        // Poll interval - low overhead but responsive
        let poll_interval = Duration::from_secs(2);

        loop {
            thread::sleep(poll_interval);

            // Acquire state safely
            let state = match app.try_state::<AppState>() {
                Some(s) => s,
                None => continue,
            };

            let mut vault = match state.vault.lock() {
                Ok(v) => v,
                Err(_) => continue, // poisoined mutex protection
            };

            if vault.should_auto_lock() {
                vault.lock_vault();

                drop(vault); // releases lock ASAP

                // Clear clipboard if we own content
                if let Some(clipboard) = app.try_state::<ClipboardState>() {
                    // Empty string triggers ownership check
                    let _ = clipboard.copy_secure(String::new());
                }

                // Notify frontend
                let _ = app.emit_all("vault_locked", ());
            }
        }
    });
}
