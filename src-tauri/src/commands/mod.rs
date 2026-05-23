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

//! Tauri command module registry.
//!
//! This module aggregates all `#[tauri::command]` handlers and re-exports
//! them for registration in `main.rs` via the [`register_commands!`] macro.
//!
//! # Usage
//! ```ignore
//! tauri::Builder::default()
//!     .invoke_handler(commands::register_commands!())
//! ```
//!
//! # Authoritative command list
//! | Command                   | Module    | Notes                             |
//! |---------------------------|-----------|-----------------------------------|
//! | `create_vault`            | vault     |                                   |
//! | `unlock_vault`            | vault     |                                   |
//! | `lock_vault`              | vault     |                                   |
//! | `vault_status`            | vault     | replaces the old `is_unlocked`    |
//! | `list_entries`            | entries   | returns `EntryView` (no password) |
//! | `add_entry`               | entries   |                                   |
//! | `update_entry`            | entries   |                                   |
//! | `delete_entry`            | entries   |                                   |
//! | `copy_to_clipboard`       | clipboard | general-purpose secure copy       |
//! | `copy_password`           | clipboard | entry password → clipboard        |
//! | `set_auto_lock_timeout`   | security  |                                   |
//! | `get_auto_lock_timeout`   | security  |                                   |
//!
//! # Removed commands
//! | Command               | Reason                                         |
//! |-----------------------|------------------------------------------------|
//! | `get_password`        | Returned raw password over IPC — security risk.|
//!                         | Use `copy_password` instead.                   |
//! | `auth::unlock_vault`  | Superseded by `vault::unlock_vault`.           |
//! | `auth::lock_vault`    | Superseded by `vault::lock_vault`.             |
//! | `auth::create_vault`  | Superseded by `vault::create_vault`.           |

pub mod auth;
pub mod clipboard;
pub mod entries;
pub mod security;
pub mod vault;

/// Expands to a `tauri::generate_handler![]` call containing every registered
/// command. Pass the result directly to `.invoke_handler()` in `main.rs`.
///
/// # Adding new commands
/// 1. Implement the handler in the appropriate submodule with `#[tauri::command]`.
/// 2. Add it to the list inside this macro.
/// 3. Update the authoritative command table in the module-level doc-comment.
#[macro_export]
macro_rules! register_commands {
    () => {
        tauri::generate_handler![
            // Vault lifecycle
            $crate::commands::vault::create_vault,
            $crate::commands::vault::unlock_vault,
            $crate::commands::vault::lock_vault,
            $crate::commands::vault::vault_status,
            // Entry CRUD
            $crate::commands::entries::list_entries,
            $crate::commands::entries::add_entry,
            $crate::commands::entries::update_entry,
            $crate::commands::entries::delete_entry,
            // Clipboard (no raw passwords returned to JS)
            $crate::commands::clipboard::copy_to_clipboard,
            $crate::commands::clipboard::copy_password,
            // Security / auto-lock policy
            $crate::commands::security::set_auto_lock_timeout,
            $crate::commands::security::get_auto_lock_timeout,
        ]
    };
}
