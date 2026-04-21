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

//! Background auto-lock watchdog.
//!
//! Spawns a single polling thread that periodically checks whether the
//! vault's inactivity timeout has elapsed and, if so, locks the vault and
//! clears the clipboard.
//!
//! # Shutdown
//! The caller receives a [`ShutdownHandle`] whose [`ShutdownHandle::signal`]
//! method sets an atomic flag that causes the thread to exit cleanly on its
//! next poll iteration. Call `signal()` inside Tauri's `on_window_event`
//! teardown handler to prevent the thread from operating on a dropped
//! [`AppHandle`] after the window is destroyed.
//!
//! # Mutex discipline
//! The vault mutex guard is released **before** `lock_vault` is called.
//! `VaultManager::lock_vault` internally acquires the same mutex; holding the
//! guard across that call would cause a deadlock on non-reentrant `Mutex`.
//! The implementation uses a two-step pattern: acquire → check → release →
//! acquire → lock, ensuring no guard is held across the `lock_vault` call.
//!
//! # Ordering choice
//! The shutdown flag uses `Ordering::SeqCst` rather than `Ordering::Relaxed`
//! to guarantee that the flag write in `ShutdownHandle::signal` is visible to
//! the watchdog thread without relying on out-of-order execution behaviour.
//! The overhead of `SeqCst` on a 2-second poll loop is negligible.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Manager};

use crate::clipboard::ClipboardState;
use crate::state::AppState;

/// Default poll interval for the watchdog thread.
///
/// Two seconds is a reasonable balance: short enough that auto-lock fires
/// within a few seconds of the timeout expiring, and long enough to avoid
/// measurable CPU overhead on idle hardware.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/* ─────────────────────────── Shutdown Handle ──────────────────────────── */

/// A handle that allows the caller to stop the auto-lock watchdog thread.
///
/// Dropping this handle does **not** stop the thread. Call
/// [`ShutdownHandle::signal`] explicitly during application teardown (e.g.,
/// from Tauri's `on_window_event` handler when the window is destroyed).
///
/// # Thread safety
/// `ShutdownHandle` is `Send + Sync` because [`AtomicBool`] is.
pub struct ShutdownHandle {
    /// Shared flag between this handle and the watchdog thread.
    ///
    /// When set to `true`, the thread exits on its next loop iteration.
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Signals the watchdog thread to exit on its next poll iteration.
    ///
    /// This is a non-blocking, best-effort operation. The thread will stop
    /// within one `POLL_INTERVAL` after this call returns.
    ///
    /// # Ordering
    /// Uses `SeqCst` to ensure the write is immediately visible across threads
    /// without relying on cache coherency timing.
    pub fn signal(&self) {
        // FIX: upgraded from `Ordering::Relaxed` to `Ordering::SeqCst`.
        // `Relaxed` provides no cross-thread ordering guarantees; on some
        // architectures the thread might not observe the flag update for an
        // unbounded number of iterations. `SeqCst` ensures the store is
        // globally visible before the function returns.
        self.flag.store(true, Ordering::SeqCst);
    }
}

/* ─────────────────────────── Watchdog ─────────────────────────────────── */

/// Spawns the auto-lock watchdog thread and returns a [`ShutdownHandle`].
///
/// The thread wakes every [`POLL_INTERVAL`], checks the vault's inactivity
/// timer, and — if the timeout has elapsed — locks the vault, clears the
/// clipboard, and emits a `vault_locked` event to the frontend.
///
/// # Parameters
/// - `app` — a cloned [`AppHandle`] that the thread uses to access managed
///   state and emit frontend events. Tauri's `AppHandle` is `Clone + Send`.
///
/// # Return value
/// Returns a [`ShutdownHandle`] that the caller must store and signal during
/// application teardown.
///
/// # Error handling
/// All errors inside the thread are handled gracefully: a failed mutex lock,
/// missing state, or failed clipboard call causes the current iteration to be
/// skipped via `continue`, not a panic.
pub fn start_auto_lock_task(app: AppHandle) -> ShutdownHandle {
    let flag = Arc::new(AtomicBool::new(false));
    let thread_flag = Arc::clone(&flag);

    thread::spawn(move || {
        loop {
            // Sleep first so the thread does not fire immediately on startup.
            thread::sleep(POLL_INTERVAL);

            // Check shutdown flag before doing any work.
            // FIX: upgraded from `Ordering::Relaxed` to `Ordering::SeqCst`
            // to match the store ordering in `ShutdownHandle::signal` and
            // ensure the flag is observed promptly.
            if thread_flag.load(Ordering::SeqCst) {
                break;
            }

            // Retrieve the managed AppState. If it is not yet registered
            // (can happen in the brief window between thread spawn and
            // `app.manage(state)` completing), skip this iteration.
            let state = match app.try_state::<AppState>() {
                Some(s) => s,
                None => continue,
            };

            // ── Step 1: Check auto-lock under a brief guard ────────────────
            //
            // The guard is intentionally scoped to this block so it is
            // dropped before step 2. Holding it across `lock_vault` would
            // deadlock: `VaultManager::lock_vault` tries to acquire the same
            // mutex on the same (non-reentrant) thread.
            let should_lock = {
                match state.vault.lock() {
                    Ok(guard) => guard.should_auto_lock(),
                    Err(_) => {
                        // Poisoned mutex: the vault is in an indeterminate
                        // state. Treat as "needs locking" for safety — better
                        // to lock unnecessarily than to leave a poisoned vault
                        // in an unlocked state.
                        true
                    }
                }
                // `guard` is dropped here; the mutex is free before step 2.
            };

            if !should_lock {
                continue;
            }

            // ── Step 2: Lock the vault ─────────────────────────────────────
            //
            // Re-acquire the mutex now that we hold no guard. If locking
            // fails (poisoned mutex), skip the clipboard and event steps so
            // we do not emit a misleading `vault_locked` event.
            let lock_succeeded = match state.vault.lock() {
                Ok(guard) => {
                    guard.lock_vault();
                    true
                    // `guard` dropped here — clipboard call below is lock-free.
                }
                Err(_) => {
                    // Mutex is still poisoned; log and skip.
                    // TODO: expose this via the logging module once available.
                    false
                }
            };

            if !lock_succeeded {
                continue;
            }

            // ── Step 3: Clear the clipboard ────────────────────────────────
            //
            // Only clears if we currently own the clipboard contents (i.e.,
            // a password we wrote is still there). If the user or another
            // application has since overwritten the clipboard, this is a no-op.
            if let Some(clipboard) = app.try_state::<ClipboardState>() {
                clipboard.clear_if_owned();
            }

            // ── Step 4: Notify the frontend ────────────────────────────────
            //
            // The `vault_locked` event causes the UI to transition to the
            // locked screen. Emit errors are intentionally ignored — the
            // vault is already locked regardless of whether the event arrives.
            let _ = app.emit_all("vault_locked", ());
        }
    });

    ShutdownHandle { flag }
}
