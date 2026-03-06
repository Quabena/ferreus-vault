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
//! This module aggregates all Tauri command handlers and exposes
//! a single function to register them with the Tauri builder.
//!
//! Keeping this centralized:
//! - Prevents command sprawl
//! - Makes auditing easier
//! - Reduces accidental public exposure
//! - Scales cleanly as features expand

pub mod clipboard;
pub mod entries;
pub mod security;
pub mod vault;

use tauri::generate_handler;

/// Returns the complete list of Tauri command handlers
///
/// This is to be called once during Tauri app initialization
///
/// Example:
/// ~~~ignore
/// tauri::Builder::default()
///     .invoke_handler(commands::register_commands())
/// ~~~
pub fn register_commands() -> impl Fn(tauri::Invoke<tauri::Wry>) + Send + Sync + 'static {
    generate_handler![
        // Vault lifecycle
        vault::create_vault,
        vault::unlock_vault,
        vault::lock_vault,
        vault::is_unlocked,
        // Entry operations
        entries::add_entry,
        entries::update_entry,
        entries::delete_entry,
        entries::get_entries,
        // Security / utililties
        security::validate_master_password,
        security::estimate_password_strength,
    ]
}
