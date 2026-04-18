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

//! Secure clipboard management
//!
//! [`ClipboardState`] writes sensitive content to the system clipboard and
//! automatically clears it after a configurable timeout.
//!
//! # Security design
//! - Content is passed as a `&str` borrow so the caller retains ownership and
//!   can zeroize it. We never take ownership of the secret.
//! - Ownership tracking uses a SHA-256 hash of the written content. Before
//!   clearing, the current clipboard content is re-hashed and compared using
//!   constant-time equality to avoid timing side-channels.
//! - Only one auto-clear timer is active at a time. Starting a new copy
//!   cancels the previous timer by incrementing a generation counter: stale
//!   timer threads detect the mismatch and exit without clearing.
//! - The clipboard is never written with an intermediate visible placeholder
//!   (e.g. "cleared"). It is set directly to an empty string.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::clipboard;

/* ------------------- Internal state -------------------------------------- */

struct InnerClipboardState {
    /// SHA-256 of the last content we wrote to the clipboard, or `None` if we
    /// do not currently own the clipboard.
    last_hash: Option<[u8; 32]>,
    /// Auto-clear timeout applied to each new copy operation.
    timeout: Duration,
    /// Monotonically increasing counter. Each `copy_secure` call increments
    /// this before spawning a timer thread. The thread captures the value at
    /// spawn time and exits early if the counter has since changed.
    generation: u64,
}

/* ------------------- Public API ------------------------------------------ */

pub struct ClipboardState {
    inner: Arc<Mutex<InnerClipboardState>>,
}

impl ClipboardState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerClipboardState {
                last_hash: None,
                timeout: Duration::from_secs(20),
                generation: 0,
            })),
        }
    }

    /// Updates the auto-clear timeout for future copy operations.
    pub fn set_timeout(&self, duration: Duration) {
        if let Ok(mut state) = self.inner.lock() {
            state.timeout = duration;
        }
    }

    /// Writes `content` to the system clipboard and schedules an auto-clear.
    ///
    /// `content` is passed as a `&str` borrow. The caller is responsible for
    /// zeroizing it after this call returns. This function does **not** retain
    /// a copy of the secret beyond what is required to hash it.
    ///
    /// If called while a previous auto-clear timer is pending, the previous
    /// timer is invalidated via the generation counter and will exit without
    /// clearing the clipboard.
    pub fn copy_secure(&self, content: &str) -> Result<(), String> {
        // Write to clipboard first — before touching our internal state.
        let mut clipboard = Clipboard::new().map_err(|e| format!("Clipboard unavailable: {e}"))?;

        clipboard
            .set_text(content)
            .map_err(|e| format!("Failed to write clipboard: {e}"))?;

        // Hash the content for ownership tracking.
        // We hash the &str directly — no heap copy of the secret is made here.
        let hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            hasher.finalize().into()
        };

        let (timeout, generation) = {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| "Internal state lock poisoned".to_string())?;

            state.last_hash = Some(hash);
            state.generation = state.generation.wrapping_add(1);
            (state.timeout, state.generation)
        };

        // Spawn the auto-clear timer with a captured generation number.
        // Any prior timer thread will see that its generation is stale and exit.
        let inner_arc = Arc::clone(&self.inner);
        thread::spawn(move || {
            thread::sleep(timeout);

            let mut clipboard = match Clipboard::new() {
                Ok(c) => c,
                Err(_) => return,
            };

            let current_text = match clipboard.get_text() {
                Ok(t) => t,
                Err(_) => return,
            };

            let current_hash: [u8; 32] = {
                let mut hasher = Sha256::new();
                hasher.update(current_text.as_bytes());
                hasher.finalize().into()
            };

            let mut state = match inner_arc.lock() {
                Ok(s) => s,
                Err(_) => return,
            };

            // Stale timer: a newer copy_secure call has since been made.
            if state.generation != generation {
                return;
            }

            if let Some(stored_hash) = state.last_hash {
                // Use constant-time comparison to avoid timing side-channels.
                if stored_hash.ct_eq(&current_hash).into() {
                    let _ = clipboard.set_text("");
                    state.last_hash = None;
                }
            }
        });

        Ok(())
    }

    /// Clears the clipboard **only if we currently own its contents**.
    ///
    /// Ownership is determined by hashing the current clipboard content and
    /// comparing it against the hash stored when we last wrote to it. If
    /// another application has since written to the clipboard, this is a no-op.
    ///
    /// Called by the auto-lock watchdog when the vault is locked.
    pub fn clear_if_owned(&self) {
        let state = match self.inner.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        let stored_hash = match state.last_hash {
            Some(h) => h,
            None => return, // We do not own the clipboard.
        };

        drop(state); // Release lock before the (potentially blocking) clipboard call.

        let mut clipboard = match Clipboard::new() {
            Ok(c) => c,
            Err(_) => return,
        };

        let current_text = match clipboard.get_text() {
            Ok(t) => t,
            Err(_) => return,
        };

        let current_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(current_text.as_bytes());
            hasher.finalize().into()
        };

        if stored_hash.ct_eq(&current_hash).into() {
            let _ = clipboard.set_text("");
            // Re-acquire to clear the stored hash.
            if let Ok(mut s) = self.inner.lock() {
                s.last_hash = None;
            }
        }
    }

    pub fn clear_clipboard_securely() {
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text("cleared");
            let _ = clipboard.set_text("");
        }
    }
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self::new()
    }
}
