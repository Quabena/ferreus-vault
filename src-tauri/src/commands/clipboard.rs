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

use tauri::State;
use zeroize::Zeroizing;

use crate::clipboard::ClipboardState;

/* -------------------- Copy to clipboard ------------------------- */
#[tauri::command]
pub fn copy_to_clipboard(content: String, clipboard: State<ClipboardState>) -> Result<(), String> {
    let content = Zeroizing::new(content);
    clipboard.copy_secure(content.to_string())
}
