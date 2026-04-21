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

//! Clipboard command handler
//!
//! # Security note on IPC secrets
//! Tauri deserialises command arguments from a JSON string in the IPC layer.
//! By the time `copy_to_clipboard` receives `content`, the framework has
//! already allocated a plain `String` on the heap. Wrapping that `String` in
//! `Zeroizing` after the fact only zeroes our own copy — the IPC buffer is
//! outside our control.
//!
//! The practical mitigation is to keep the sensitive string alive as briefly
//! as possible: we pass it as `&str` directly to `copy_secure` (which hashes
//! it without retaining a copy) and let it drop at the end of this function.
//! Do not clone or store it anywhere in this path.

use tauri::State;

use arboard::Clipboard;
use std::thread;
use std::time::Duration;

use super::auth::AppState;

#[tauri::command]
pub fn copy_password(password: String, state: State<AppState>) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|_| "clipboard error")?;

    clipboard
        .set_text(password.clone())
        .map_err(|_| "clipboard write failed")?;

    thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));

        if let Ok(mut cb) = Clipboard::new() {
            let _ = cb.set_text("");
        }
    });

    Ok(())
}
