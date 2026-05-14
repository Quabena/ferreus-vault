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

//! Authentication command handlers (legacy module — kept for compatibility).
//!
//! # Role of this file
//! The vault lifecycle commands (`create_vault`, `unlock_vault`, `lock_vault`)
//! have been fully superseded by [`super::vault`], which uses the correct
//! [`crate::state::AppState`] backed by a `Mutex<VaultManager>`.
//!
//! This module previously defined its own `AppState` wrapping
//! `Arc<VaultData>` directly — an approach that is both architecturally wrong
//! (bypasses `VaultManager`'s lock/unlock/KDF machinery) and unsound (methods
//! like `unlock`, `lock`, and `initialize` do not exist on `VaultData`).
//!
//! **This module no longer exports command handlers or a conflicting
//! `AppState`.** It is retained as an empty shell so that any existing
//! `mod auth;` declarations in `mod.rs` continue to compile without churn.
//! The commands it used to contain live in [`super::vault`] and are registered
//! there.
//!
//! # Migration
//! | Old symbol                  | New location              |
//! |-----------------------------|---------------------------|
//! | `auth::AppState`            | `crate::state::AppState`  |
//! | `auth::create_vault`        | `vault::create_vault`     |
//! | `auth::unlock_vault`        | `vault::unlock_vault`     |
//! | `auth::lock_vault`          | `vault::lock_vault`       |
//!
//! # What was wrong in the original file
//! 1. **`AppState` duplicated `crate::state::AppState`** — two structs with
//!    the same name in scope caused ambiguous-type compile errors throughout
//!    the `entries` and `security` modules that imported both.
//! 2. **`Arc<VaultData>` is the wrong type for vault state** — `VaultData` is
//!    the *plaintext, decrypted* vault contents; it has no `unlock`, `lock`,
//!    or `initialize` methods. Those live on `VaultManager`. Wrapping
//!    `VaultData` in an `Arc` provides no locking, no key management, and no
//!    persistence.
//! 3. **`vault.unlock(password.as_bytes())`** — `VaultData` has no `unlock`
//!    method. This would fail to compile against the actual library API.
//! 4. **`vault.initialize(password.as_bytes())`** — same: no such method on
//!    `VaultData`.
//! 5. **Error messages leaked internal `Debug` output** —
//!    `format!("{:?}", e)` on a `VaultError` forwards implementation-specific
//!    detail over the IPC channel. All three handlers used this pattern.
//! 6. **Wrong crate name** — imported from `ferreus_core`; the library crate
//!    is named `ferreus_vault`.
