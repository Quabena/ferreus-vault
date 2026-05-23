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

//! Application entry point for the FerreusVault Tauri desktop shell.
//!
//! # Startup sequence
//! 1. [`AppState`] is initialised (vault directory created, vault manager
//!    constructed in the locked state).
//! 2. [`ClipboardState`] is registered.
//! 3. The auto-lock watchdog thread is started **after** both states are
//!    registered, preventing a race where the thread tries to access state
//!    that has not yet been passed to `app.manage()`.
//! 4. A [`ShutdownState`] wrapping the watchdog handle is registered so the
//!    `on_window_event` handler can signal shutdown by taking the handle out
//!    of the `Option`.
//!
//! # Shutdown sequence
//! When the main window is destroyed, `on_window_event` signals the watchdog
//! thread via [`ShutdownHandle::signal`] and drops the handle. The thread
//! exits within one poll interval (~2 s).
//!
//! # Windows subsystem
//! The `windows_subsystem = "windows"` attribute suppresses the console window
//! in release builds. Debug builds retain the console for log output.

// Suppress the console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auto_lock;
mod clipboard;
mod commands;
mod state;

use auto_lock::ShutdownHandle;
use clipboard::ClipboardState;
use state::AppState;

use std::sync::Mutex;
use tauri::Manager;

/* ─────────────────────────── Shutdown State ───────────────────────────── */

/// Tauri-managed wrapper for the auto-lock watchdog's [`ShutdownHandle`].
///
/// Wrapping the handle in `Mutex<Option<_>>` allows `on_window_event` to
/// **take** the handle exactly once (leaving `None` behind) and call
/// `signal()` without risk of double-signalling.
pub struct ShutdownState {
    pub handle: Mutex<Option<ShutdownHandle>>,
}

/* ─────────────────────────── Entry Point ──────────────────────────────── */

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();

            // `AppState::new` resolves the vault directory, creates it if absent
            // (with mode 0o700 on Unix), and constructs a locked `VaultManager`.
            // Failure surfaces as a Tauri setup error with a user-facing dialog.
            let state = AppState::new(&app_handle)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            app.manage(state);

            // ── 2. Register clipboard state ────────────────────────────────
            app.manage(ClipboardState::new());

            // ── 3. Start the auto-lock watchdog ────────────────────────────
            //
            // IMPORTANT: The watchdog must be started AFTER `app.manage(state)`
            // and `app.manage(ClipboardState::new())` above. The watchdog
            // thread calls `app.try_state::<AppState>()` on each iteration;
            // if it starts before state is registered, `try_state` returns
            // `None` and the iteration is silently skipped — but this creates
            // a brief window where auto-lock does not function. Keeping this
            // order avoids the race entirely.
            let handle = auto_lock::start_auto_lock_task(app_handle.clone());

            // ── 4. Store the shutdown handle ───────────────────────────────
            app.manage(ShutdownState {
                handle: Mutex::new(Some(handle)),
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Signal the watchdog thread to stop when the window is destroyed.
            //
            // Using `WindowEvent::Destroyed` (rather than `CloseRequested`)
            // ensures the thread is stopped only when the window is fully gone,
            // not when the user merely requests a close that might be cancelled.
            if let tauri::WindowEvent::Destroyed = event {
                let app_handle = window.app_handle();

                if let Some(state) = app_handle.try_state::<ShutdownState>() {
                    // `take()` leaves `None` behind, making a second `Destroyed`
                    // event (which some platforms emit) a safe no-op.
                    // Using `if let` rather than `unwrap` degrades gracefully
                    // if the mutex is poisoned during teardown.
                    if let Ok(mut guard) = state.handle.lock() {
                        if let Some(handle) = guard.take() {
                            handle.signal();
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            // Vault lifecycle
            commands::vault::create_vault,
            commands::vault::unlock_vault,
            commands::vault::lock_vault,
            commands::vault::vault_status,
            // Entry CRUD
            commands::entries::add_entry,
            commands::entries::update_entry,
            commands::entries::delete_entry,
            commands::entries::list_entries,
            // Clipboard
            commands::clipboard::copy_to_clipboard,
            commands::clipboard::copy_password,
            // Security policy
            commands::security::set_auto_lock_timeout,
            commands::security::get_auto_lock_timeout,
        ])
        .run(tauri::generate_context!())
        .expect("fatal: FerreusVault failed to start");
}
