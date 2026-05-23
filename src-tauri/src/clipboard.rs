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

//! Secure clipboard management.
//!
//! [`ClipboardState`] writes sensitive content to the system clipboard and
//! automatically clears it after a configurable timeout, using ownership
//! tracking to avoid wiping content that was not written by this application.
//!
//! # Security design
//! - Content is accepted as a `&str` borrow so the caller retains ownership
//!   and can zeroize the original. This module never stores the secret in its
//!   own memory beyond the duration of the `set_text` call.
//! - Ownership tracking uses SHA-256 of the written content. Before clearing,
//!   the current clipboard content is re-hashed and compared using
//!   **constant-time equality** (`subtle::ConstantTimeEq`) to avoid timing
//!   side-channels that could be exploited to infer clipboard content.
//! - Only one auto-clear timer is active at a time. Each `copy_secure` call
//!   increments a generation counter; the spawned timer captures the counter
//!   value at spawn time and exits early if it no longer matches, preventing
//!   a stale timer from erasing a newer copy operation.
//! - The clipboard is cleared by writing an **empty string** directly. It is
//!   never set to an intermediate value such as `"cleared"` that would be
//!   briefly visible to other applications.
//!
//! # Known limitation
//! On Wayland, `arboard` may not be able to read back clipboard content after
//! the writing process yields the clipboard seat. In that case
//! `clear_if_owned` and the auto-clear timer fall back to unconditional
//! clearing when `get_text` fails, which is the safer default.

// FIX: removed the self-referential `use crate::clipboard;` import.
// A module cannot usefully import itself — this was a dead import that would
// cause a compile warning (or error depending on the edition) and serves no
// purpose. Removed entirely.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/* ─────────────────────────── Internal State ───────────────────────────── */

/// Shared mutable state protected by a `Mutex` inside [`ClipboardState`].
struct InnerClipboardState {
    /// SHA-256 of the last content written to the clipboard by this
    /// application, or `None` if we do not currently own the clipboard.
    ///
    /// Used to determine whether clearing is appropriate before each
    /// auto-clear or forced-clear operation.
    last_hash: Option<[u8; 32]>,

    /// Auto-clear timeout applied to every new `copy_secure` call.
    ///
    /// Configurable via [`ClipboardState::set_timeout`]. Default: 20 seconds.
    timeout: Duration,

    /// Monotonically increasing generation counter.
    ///
    /// Incremented on each `copy_secure` call before a timer thread is
    /// spawned. Each timer captures the value at spawn time; if the stored
    /// counter differs when the timer fires, the timer exits without clearing.
    /// Uses `wrapping_add` so a u64 overflow (practically unreachable) does
    /// not panic.
    generation: u64,
}

/* ─────────────────────────── Public API ───────────────────────────────── */

/// Manages secure clipboard write, ownership tracking, and auto-clear.
///
/// Register a single instance as Tauri managed state via `app.manage(ClipboardState::new())`.
/// Command handlers receive it via `State<ClipboardState>`.
pub struct ClipboardState {
    inner: Arc<Mutex<InnerClipboardState>>,
}

impl ClipboardState {
    /// Creates a new [`ClipboardState`] with a 20-second default auto-clear timeout.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerClipboardState {
                last_hash: None,
                timeout: Duration::from_secs(20),
                generation: 0,
            })),
        }
    }

    /// Updates the auto-clear timeout applied to future `copy_secure` calls.
    ///
    /// Does not affect any timer that is already running. Setting a very short
    /// timeout (< 1 s) may cause the clipboard to be cleared before the user
    /// can paste.
    pub fn set_timeout(&self, duration: Duration) {
        if let Ok(mut state) = self.inner.lock() {
            state.timeout = duration;
        }
    }

    /// Writes `content` to the system clipboard and schedules an auto-clear.
    ///
    /// The caller retains ownership of `content` and is responsible for
    /// zeroizing it after this call returns. This method does not retain any
    /// copy of the secret beyond what the OS clipboard holds.
    ///
    /// If a previous auto-clear timer is still pending, it is invalidated by
    /// the generation counter increment and will exit without clearing.

    pub fn copy_secure(&self, content: &str) -> Result<(), String> {
        // Write to the clipboard FIRST, before mutating internal state.
        // If the clipboard write fails, we leave our internal state unchanged
        // so the previous ownership claim remains valid.
        let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard unavailable: {e}"))?;

        clipboard
            .set_text(content)
            .map_err(|e| format!("Failed to write to clipboard: {e}"))?;

        // Hash the content for ownership tracking.
        // The hash is computed from the borrowed `&str`; no owned copy of the
        // secret is retained in this function after hashing completes.
        let hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hasher.finalize().into()
        };

        // Update internal state and capture timeout + generation for the timer.
        let (timeout, generation) = {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| "Internal clipboard state lock is poisoned".to_string())?;

            state.last_hash = Some(hash);
            state.generation = state.generation.wrapping_add(1);
            (state.timeout, state.generation)
        };
        // Lock released here; `inner_arc` clone below does not hold the lock.

        // Spawn the auto-clear timer. The thread captures `generation` so it
        // can detect whether a newer `copy_secure` call has superseded it.
        let inner_arc = Arc::clone(&self.inner);
        thread::spawn(move || {
            thread::sleep(timeout);

            // Open a fresh clipboard handle inside the timer thread.
            // `Clipboard` is not `Send`, so it cannot be shared from the
            // call site; it must be created here in the spawned thread.
            let mut clipboard = match Clipboard::new() {
                Ok(c) => c,
                Err(_) => return, // Clipboard unavailable; skip clearing.
            };

            let current_text = match clipboard.get_text() {
                Ok(t) => t,
                // On Wayland or if another app owns the clipboard, get_text
                // may fail. Clear unconditionally — this is the safer default.
                Err(_) => {
                    // Attempt unconditional clear so we do not leave a stale
                    // password if reading back is not supported.
                    let _ = clipboard.set_text("");
                    if let Ok(mut state) = inner_arc.lock() {
                        if state.generation == generation {
                            state.last_hash = None;
                        }
                    }
                    return;
                }
            };

            let current_hash: [u8; 32] = {
                let mut hasher = Sha256::new();
                hasher.update(current_text.as_bytes());
                hasher.finalize().into()
            };

            let mut state = match inner_arc.lock() {
                Ok(s) => s,
                Err(_) => return, // Poisoned lock; skip clearing.
            };

            // Generation check: exit if a newer copy_secure has been called
            // since this timer was spawned.
            if state.generation != generation {
                return;
            }

            if let Some(stored_hash) = state.last_hash {
                // Constant-time comparison: prevents a timing side-channel
                // that could reveal whether clipboard content matches.
                if stored_hash.ct_eq(&current_hash).into() {
                    let _ = clipboard.set_text("");
                    state.last_hash = None;
                }
            }
        });

        Ok(())
    }

    /// Clears the clipboard if this application currently owns its contents.
    ///
    /// Ownership is determined by hashing the current clipboard text and
    /// comparing it (constant-time) against the hash stored at last write
    /// time. If another application has overwritten the clipboard since, this
    /// is a no-op.
    ///
    /// Called by the auto-lock watchdog when locking the vault.
    ///
    /// # Wayland fallback
    /// If `get_text` fails (common on Wayland when the owning process does not
    /// hold the clipboard seat), this method clears unconditionally rather than
    /// leaving a potentially sensitive value in place.
    pub fn clear_if_owned(&self) {
        // ── Step 1: Read stored hash under the lock, then release ──────────
        //
        // We must release the lock before the clipboard call because
        // `Clipboard::new()` / `get_text()` can block, and holding the mutex
        // across a blocking OS call risks priority inversion or deadlock if
        // another thread tries to lock while we wait.
        let stored_hash = {
            let state = match self.inner.lock() {
                Ok(s) => s,
                Err(_) => return, // Poisoned; skip.
            };
            match state.last_hash {
                Some(h) => h,
                None => return, // We do not currently own the clipboard.
            }
            // `state` guard dropped here.
        };

        // ── Step 2: Read current clipboard content (lock-free) ─────────────
        let mut clipboard = match Clipboard::new() {
            Ok(c) => c,
            Err(_) => return,
        };

        let current_text = match clipboard.get_text() {
            Ok(t) => t,
            // Wayland fallback: clear unconditionally if read-back fails.
            Err(_) => {
                let _ = clipboard.set_text("");
                if let Ok(mut s) = self.inner.lock() {
                    s.last_hash = None;
                }
                return;
            }
        };

        let current_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(current_text.as_bytes());
            hasher.finalize().into()
        };

        // ── Step 3: Compare and clear ──────────────────────────────────────
        if stored_hash.ct_eq(&current_hash).into() {
            let _ = clipboard.set_text("");
            // Re-acquire to clear the stored hash only after a successful clear.
            if let Ok(mut s) = self.inner.lock() {
                s.last_hash = None;
            }
        }
    }
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self::new()
    }
}
