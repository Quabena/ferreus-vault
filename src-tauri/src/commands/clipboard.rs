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

use crate::clipboard::ClipboardState;

/* -------------------- Copy to clipboard ---------------------------------- */

/// Writes `content` to the system clipboard and arms the auto-clear timer.
///
/// `content` is borrowed (not cloned) before being passed to `copy_secure`,
/// so no additional heap copy of the secret is made in this function.
#[tauri::command]
pub fn copy_to_clipboard(content: String, clipboard: State<ClipboardState>) -> Result<(), String> {
    // Pass as &str — copy_secure accepts a borrow and does not retain a copy.
    // The `content` String is dropped at the end of this function.
    clipboard.copy_secure(&content)
}
