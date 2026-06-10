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

//! Core vault data structures.
//!
//! Defines the plaintext, in-memory representation of vault contents.
//! The entire structure is serialized and encrypted as a single unit by
//! [`crate::crypto::EncryptedVault`] — no individual field is ever written to
//! disk in plaintext.
//!
//! # Security goals
//! - Sensitive fields are zeroized on drop via [`ZeroizeOnDrop`].
//! - Schema is versioned for forward compatibility.
//! - No accidental data leakage through derived trait impls (e.g., no `Display`
//!   on types that contain secret fields).
//! - All mutations update a vault-level `last_modified` timestamp for audit.
//!
//! # Data model
//! ```text
//! VaultData
//! └── Vec<PasswordEntry>
//!     ├── account_name  (non-secret; used for search and display)
//!     ├── username      (secret; zeroized on drop)
//!     ├── password      (secret; zeroized on drop)
//!     ├── notes         (secret; zeroized on drop)
//!     ├── created_at    (non-secret timestamp)
//!     └── updated_at    (non-secret timestamp)
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::VaultError;

/// A single credential record stored in the vault.
///
/// # Zeroization policy
/// - `username`, `password`, and `notes` are **sensitive** and are zeroized
///   when the entry is dropped.
/// - `account_name` and the timestamp fields are intentionally **not**
///   zeroized because they are used for search, UI listing, and audit purposes
///   and are not considered secret on their own.
///
/// # Encryption
/// Entries are never individually encrypted. The entire [`VaultData`] struct
/// (which contains all entries) is serialized and encrypted as one unit by
/// [`crate::crypto::EncryptedVault`]. Do not store individual entries outside
/// of a locked [`crate::VaultManager`].
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    /// Human-readable account or service name (e.g., "Gmail").
    ///
    /// Not considered sensitive — used for search and display.
    /// Exempt from zeroization.
    #[zeroize(skip)]
    pub account_name: String,

    /// Login username or email address.
    ///
    /// Considered sensitive; zeroized on drop.
    pub username: String,

    /// Account password or secret token.
    ///
    /// Considered sensitive; zeroized on drop.
    pub password: String,

    /// Optional free-text notes attached to this entry.
    ///
    /// Considered sensitive (may contain security questions, recovery codes,
    /// etc.); zeroized on drop.
    pub notes: String,

    /// UTC timestamp at which this entry was first created.
    ///
    /// Not zeroized; used for audit and display.
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// UTC timestamp of the most recent modification to any field.
    ///
    /// Not zeroized; used for conflict detection and display.
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>,
}

impl PasswordEntry {
    /// Creates a new entry with the current UTC timestamp as `created_at` and
    /// `updated_at`.
    ///
    /// # Parameters
    /// All string parameters are moved into the entry. Callers holding
    /// sensitive string values should use [`Zeroizing<String>`] at the call
    /// site and let the value move out of the wrapper naturally.
    pub fn new(
        account_name: String,
        username: String,
        password: String,
        notes: String,
    ) -> Self {
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

    /// Updates selected fields of the entry.
    ///
    /// `updated_at` is refreshed to the current UTC time if **any** field
    /// value changes. Passing `None` for a field leaves it unchanged.
    ///
    /// # Security note
    /// Old field values are overwritten in place. The old `String` allocation
    /// is freed by Rust's allocator; whether the old bytes are scrubbed from
    /// memory depends on the allocator. For the strongest guarantee, the caller
    /// should zeroize the old values before passing new ones. In practice, the
    /// entire entry is zeroized when the containing [`VaultData`] is dropped.
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

/// The top-level plaintext vault container.
///
/// Serialized with `bincode` and encrypted as a single opaque blob by
/// [`crate::crypto::EncryptedVault`]. No individual field reaches disk in
/// plaintext.
///
/// # Version history
/// | Version | Changes                                    |
/// |---------|--------------------------------------------|
/// | 1       | Initial release; entries are a flat `Vec`. |
///
/// When a backward-incompatible format change is made, increment
/// [`VaultData::CURRENT_VERSION`] and add a migration in `storage.rs`.
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    /// Schema version — checked on load to detect incompatible formats.
    ///
    /// Must equal [`VaultData::CURRENT_VERSION`]; mismatches are surfaced as
    /// [`crate::errors::VaultError::CorruptedVault`].
    pub version: u32,

    /// All stored password entries.
    ///
    /// Entries are stored in insertion order. Index-based access is used for
    /// update and delete; callers should use [`VaultData::find_entries`] for
    /// search rather than assuming stable indices.
    pub entries: Vec<PasswordEntry>,

    /// UTC timestamp when this vault was first created.
    ///
    /// Not zeroized; used for audit and display.
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// UTC timestamp of the most recent modification to any entry or metadata.
    ///
    /// Not zeroized; used for conflict detection.
    #[zeroize(skip)]
    pub last_modified: DateTime<Utc>,
}

impl VaultData {
    /// The current vault schema version.
    ///
    /// Increment this constant when the serialized format changes in a
    /// backward-incompatible way, and add a migration path in `storage.rs`.
    pub const CURRENT_VERSION: u32 = 1;

    /// Creates an empty vault with the current schema version and the current
    /// UTC time as both `created_at` and `last_modified`.
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

    /// Removes and returns the entry at `index`, shifting subsequent entries.
    ///
    /// # Errors
    /// Returns [`VaultError::EntryNotFound`] if `index` is out of bounds.
    ///
    /// # Note on indices
    /// Removing an entry changes the indices of all subsequent entries. If you
    /// are iterating and removing, collect indices first and remove in reverse
    /// order, or use [`VaultData::find_entries`] to locate entries by content.
    pub fn remove_entry(&mut self, index: usize) -> Result<PasswordEntry, VaultError> {
        if index >= self.entries.len() {
            return Err(VaultError::EntryNotFound);
        }
        let removed = self.entries.remove(index);
        self.touch();
        Ok(removed)
    }

    /// Updates selected fields of the entry at `index`.
    ///
    /// Passing `None` for a field leaves it unchanged. `updated_at` on the
    /// entry is refreshed automatically if any field value changes.
    ///
    /// # Errors
    /// Returns [`VaultError::EntryNotFound`] if `index` is out of bounds.
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

    /// Returns a shared reference to the entry at `index`, or `None` if the
    /// index is out of bounds.
    pub fn get_entry(&self, index: usize) -> Option<&PasswordEntry> {
        self.entries.get(index)
    }

    /// Returns all entries whose `account_name`, `username`, or `notes`
    /// fields contain `query` (case-insensitive substring match).
    ///
    /// # Security
    /// This operates **exclusively on decrypted in-memory data**. It never
    /// reads from disk and never constructs a query against ciphertext.
    /// The vault must be unlocked before calling this method.
    ///
    /// # Performance
    /// Linear scan over all entries. For typical vault sizes (< 1000 entries)
    /// this is negligible; if performance becomes a concern, consider
    /// maintaining a separate in-memory index.
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

    /// Updates the vault-level `last_modified` timestamp to the current UTC time.
    fn touch(&mut self) {
        self.last_modified = Utc::now();
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}
