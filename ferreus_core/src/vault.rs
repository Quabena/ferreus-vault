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

//! Core vault data structures
//!
//! Defines the plaintext in-memory representation of vault contents.
//! The entire structure is serialized and encrypted as a single unit by
//! [`crate::crypto::EncryptedVault`] — no individual field is ever written
//! to disk in plaintext.
//!
//! Security goals:
//! - Sensitive fields are zeroized on drop via `ZeroizeOnDrop`
//! - Schema is versioned for forward compatibility
//! - No accidental data leakage through derived trait impls (e.g. no `Display`)
//! - Audit-friendly and explicit behaviour

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::VaultError;

/// A single credential stored in the vault.
///
/// # Zeroization
/// `username`, `password`, and `notes` are treated as sensitive and are
/// zeroized when the entry is dropped. `account_name` and the timestamp fields
/// are intentionally **not** zeroized because they are used for search, UI
/// listing, and audit purposes.
///
/// # Encryption
/// Entries are never individually encrypted. The entire [`VaultData`] struct
/// (which contains all entries) is serialized and encrypted as one unit.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    /// Human-readable account or service name (e.g. "Gmail").
    ///
    /// Not considered sensitive — used for search and display.
    #[zeroize(skip)]
    pub account_name: String,

    /// Login username or email address.
    pub username: String,

    /// Account password or secret token.
    pub password: String,

    /// Optional free-text notes attached to this entry.
    pub notes: String,

    /// Timestamp at which this entry was first created.
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// Timestamp of the most recent modification to any field.
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Creates a new entry with the current UTC timestamp.
    pub fn new(account_name: String, username: String, password: String, notes: String) -> Self {
        let now = Utc::now();
        Self {
            account_name,
            username,
            password,
            notes,
            created_at: now,
            updated_at: now,
        }
    }

    /// Updates selected fields.
    ///
    /// `updated_at` is refreshed automatically if any field value changes.
    /// Passing `None` for a field leaves it unchanged.
    pub fn update(
        &mut self,
        account_name: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) {
        let mut modified = false;

        if let Some(v) = account_name {
            self.account_name = v;
            modified = true;
        }
        if let Some(v) = username {
            self.username = v;
            modified = true;
        }
        if let Some(v) = password {
            self.password = v;
            modified = true;
        }
        if let Some(v) = notes {
            self.notes = v;
            modified = true;
        }

        if modified {
            self.updated_at = Utc::now();
        }
    }
}

/* ------------------- VaultData ------------------------------------------ */

/// The top-level plaintext vault container.
///
/// Serialized with `bincode` and encrypted as a single opaque blob by
/// [`crate::crypto::EncryptedVault`]. No individual field reaches disk in
/// plaintext.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    /// Schema version — checked on load to detect incompatible formats.
    pub version: u32,

    /// All stored password entries.
    pub entries: Vec<PasswordEntry>,

    /// UTC timestamp when this vault was first created.
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// UTC timestamp of the most recent modification.
    #[zeroize(skip)]
    pub last_modified: DateTime<Utc>,
}

impl VaultData {
    /// The current vault schema version. Bump this when the serialized format
    /// changes in a backwards-incompatible way.
    pub const CURRENT_VERSION: u32 = 1;

    /// Creates an empty vault with the current schema version and timestamp.
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            version: Self::CURRENT_VERSION,
            entries: Vec::new(),
            created_at: now,
            last_modified: now,
        }
    }

    /// Appends a new entry and updates the vault modification timestamp.
    pub fn add_entry(&mut self, entry: PasswordEntry) {
        self.entries.push(entry);
        self.touch();
    }

    /// Removes and returns the entry at `index`.
    ///
    /// Returns [`VaultError::EntryNotFound`] if the index is out of bounds.
    pub fn remove_entry(&mut self, index: usize) -> Result<PasswordEntry, VaultError> {
        if index >= self.entries.len() {
            return Err(VaultError::EntryNotFound);
        }
        let removed = self.entries.remove(index);
        self.touch();
        Ok(removed)
    }

    /// Updates selected fields on the entry at `index`.
    ///
    /// Returns [`VaultError::EntryNotFound`] if the index is out of bounds.
    pub fn update_entry(
        &mut self,
        index: usize,
        account_name: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) -> Result<(), VaultError> {
        let entry = self
            .entries
            .get_mut(index)
            .ok_or(VaultError::EntryNotFound)?;

        entry.update(account_name, username, password, notes);
        self.touch();
        Ok(())
    }

    /// Returns the entry at `index`, or `None` if the index is out of bounds.
    pub fn get_entry(&self, index: usize) -> Option<&PasswordEntry> {
        self.entries.get(index)
    }

    /// Case-insensitive search over `account_name`, `username`, and `notes`.
    ///
    /// # Security
    /// This operates **exclusively on decrypted in-memory data**. It never
    /// reads from disk and never constructs a query against the ciphertext.
    /// The vault must be unlocked before calling this method.
    pub fn find_entries(&self, query: &str) -> Vec<&PasswordEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.account_name.to_lowercase().contains(&query_lower)
                    || e.username.to_lowercase().contains(&query_lower)
                    || e.notes.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Updates the vault-level modification timestamp.
    fn touch(&mut self) {
        self.last_modified = Utc::now();
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}
