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
use core::time;
use std::hash::Hasher;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use arboard::Clipboard;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::{clipboard, state};

/* ---------------------------- Clipboard State ----------------------------- */
pub struct ClipboardState {
    inner: Arc<Mutex<InnerClipboardstate>>,
}

struct InnerClipboardstate {
    last_hash: Option<[u8; 32]>,
    timeout: Duration,
}

impl ClipboardState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerClipboardstate {
                last_hash: None,
                timeout: Duration::from_secs(20), // default auto-clear
            })),
        }
    }

    pub fn set_timeout(&self, duration: Duration) {
        if let Ok(mut state) = self.inner.lock() {
            state.timeout = duration;
        }
    }

    pub fn copy_secure(&self, content: String) -> Result<(), String> {
        let content = Zeroizing::new(content);

        let mut clipboard = Clipboard::new().map_err(|_| "Clipboard unavailable".to_string())?;

        clipboard
            .set_text(content.to_string())
            .map_err(|_| "Failed to write clipboard".to_string())?;

        // Hash clipboard content to track ownership
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        let inner_arc = self.inner.clone();

        {
            let mut state = inner_arc
                .lock()
                .map_err(|_| "Internal state error".to_string())?;

            state.last_hash = Some(hash);
        }

        // Spawn auto-clear thread
        thread::spawn(move || {
            let timeout;
            {
                let state = match inner_arc.lock() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                timeout = state.timeout;
            }
            thread::sleep(timeout);

            let mut clipboard = match Clipboard::new() {
                Ok(c) => c,
                Err(_) => return,
            };

            let current = match clipboard.get_text() {
                Ok(text) => text,
                Err(_) => return,
            };

            let mut hasher = Sha256::new();
            hasher.update(current.as_bytes());
            let current_hash: [u8; 32] = hasher.finalize().into();

            let mut state = match inner_arc.lock() {
                Ok(s) => s,
                Err(_) => return,
            };

            // Only clear if clipboard still contains our data
            if let Some(stored_hash) = state.last_hash {
                if stored_hash == current_hash {
                    let _ = clipboard.set_text(String::new());
                    state.last_hash = None;
                }
            }
        });

        Ok(())
    }
}
