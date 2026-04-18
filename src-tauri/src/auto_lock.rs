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

//! Background auto-lock watchdog
//!
//! Spawns a single polling thread that periodically checks whether the
//! inactivity timeout has elapsed and, if so, locks the vault and clears
//! the clipboard.
//!
//! # Shutdown
//! The caller receives a [`ShutdownHandle`] whose `signal()` method sets an
//! atomic flag that causes the thread to exit cleanly on its next iteration.
//! Call `signal()` inside Tauri's `on_window_event` or `setup` teardown to
//! avoid the thread operating on a dropped [`AppHandle`].
//!
//! # Mutex discipline
//! The vault mutex is released **before** `lock_vault` is called and before
//! any other shared state is touched. This prevents the deadlock that would
//! occur if `lock_vault` tried to re-acquire the mutex while this thread
//! still held the guard.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Manager};

use crate::clipboard::ClipboardState;
use crate::state::AppState;

/* ------------------- Shutdown handle ------------------------------------- */

/// Allows the caller to signal the auto-lock thread to stop.
///
/// Dropping the handle does **not** stop the thread — call [`ShutdownHandle::signal`]
/// explicitly during application teardown.
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Signals the watchdog thread to exit on its next poll iteration.
    pub fn signal(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/* ------------------- Watchdog -------------------------------------------- */

/// Spawns the auto-lock watchdog thread and returns a [`ShutdownHandle`].
///
/// The thread polls every `poll_interval` and calls `lock_vault` + clipboard
/// clear when the inactivity timeout has elapsed.
///
/// # Panics
/// Does not panic. All errors inside the thread are handled gracefully by
/// `continue`-ing to the next iteration.
pub fn start_auto_lock_task(app: AppHandle) -> ShutdownHandle {
    let flag = Arc::new(AtomicBool::new(false));
    let thread_flag = Arc::clone(&flag);

    thread::spawn(move || {
        let poll_interval = Duration::from_secs(2);

        loop {
            thread::sleep(poll_interval);

            // Exit cleanly when the caller signals shutdown.
            if thread_flag.load(Ordering::Relaxed) {
                break;
            }

            let state = match app.try_state::<AppState>() {
                Some(s) => s,
                None => continue,
            };

            // Check whether auto-lock should fire, then release the guard
            // BEFORE calling lock_vault. Calling lock_vault while holding the
            // MutexGuard would attempt to re-acquire the same mutex on the
            // same thread, causing a deadlock.
            let should_lock = {
                match state.vault.lock() {
                    Ok(v) => v.should_auto_lock(),
                    Err(_) => {
                        // Poisoned mutex — the vault is in an unknown state.
                        // Treat as needing a lock for safety.
                        true
                    }
                }
                // Guard is dropped here, before any further mutex work.
            };

            if should_lock {
                // Re-acquire to call lock_vault now that no guard is held.
                if let Ok(v) = state.vault.lock() {
                    v.lock_vault();
                }
                // Guard released here before we touch ClipboardState.

                // Clear clipboard ownership-aware: only clears if the
                // clipboard still contains content we wrote.
                if let Some(clipboard) = app.try_state::<ClipboardState>() {
                    clipboard.clear_if_owned();
                }

                // Notify the frontend so the UI can transition to the locked screen.
                let _ = app.emit_all("vault_locked", ());
            }
        }
    });

    ShutdownHandle { flag }
}
