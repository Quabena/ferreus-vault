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

//! Tauri command module registry
//!
//! This module aggregates all Tauri command handlers and exposes a single
//! `register_commands()` function for use during Tauri app initialisation.
//!
//! # Keeping this file accurate
//! Every `#[tauri::command]` function that should be callable from the
//! frontend **must** appear in `register_commands()`. Functions that exist
//! in submodules but are not listed here are unreachable from JavaScript.
//!
//! # Authoritative command list
//! | Command                    | Module     | Notes                          |
//! |----------------------------|------------|--------------------------------|
//! | create_vault               | vault      |                                |
//! | unlock_vault               | vault      |                                |
//! | lock_vault                 | vault      |                                |
//! | vault_status               | vault      | replaces the old is_unlocked   |
//! | list_entries               | entries    | replaces the old get_entries   |
//! | add_entry                  | entries    |                                |
//! | update_entry               | entries    |                                |
//! | delete_entry               | entries    |                                |
//! | copy_to_clipboard          | clipboard  |                                |
//! | set_auto_lock_timeout      | security   |                                |
//! | get_auto_lock_timeout      | security   |                                |

pub mod clipboard;
pub mod entries;
pub mod security;
pub mod vault;

use tauri::generate_handler;

/// Returns the complete list of registered Tauri command handlers.
///
/// Call this exactly once during Tauri app initialisation:
///
/// ```ignore
/// tauri::Builder::default()
///     .invoke_handler(commands::register_commands())
/// ```
pub fn register_commands() -> impl Fn(tauri::Invoke<tauri::Wry>) + Send + Sync + 'static {
    generate_handler![
        // Vault lifecycle
        vault::create_vault,
        vault::unlock_vault,
        vault::lock_vault,
        vault::vault_status,
        // Entry operations
        entries::list_entries,
        entries::add_entry,
        entries::update_entry,
        entries::delete_entry,
        // Clipboard
        clipboard::copy_to_clipboard,
        // Security / auto-lock policy
        security::set_auto_lock_timeout,
        security::get_auto_lock_timeout,
    ]
}
