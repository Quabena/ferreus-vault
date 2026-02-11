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
//! This module defines the plaintext in-memory representation of vault data
//! The entire structure is expected to be serialized and encrypted as a single unit
//! 
//! Security goals:
//! - Sensitive fields are zeroized on drop
//! - Schema is versioned for forward compatibility
//! - Minimal accidental data leakage
//! - Audit-friendly and explicit behaviour

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::VaultError;

/// Represent a single credential stored in the vault
///
/// NOTE:
/// - `password`, `username`, and `notes` are treated as sensitive.
/// - `account_name` is intentionally not zeroized because it is used for search and UI listing.
/// - All entried are encrypted together as part of 'VaultData'
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    /// Human-readable account/service name (eg. 'gmail')
    #[zeroize(skip)]
    pub account_name: String,

    /// Login username or email
    pub username: String,

    /// Account password or secret
    pub password: String,

    /// Optional user notes
    pub notes: String,

    /// Entry creation timestamp
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// Last modification timestamp
    #[zeroize(skip)]
    pub updated_at: DateTime<Utc>
}

impl PasswordEntry {
    /// Create a new vault entry with current timestamp
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
            created_at,
            updated_at,
        }
    }

    /// Updates selected fields of an entry
    /// 
    /// The timestamp is automatically refreshed if any field changes
    pub fn update(
        &mut self,
        account_name: Option<String>,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
    ) {
        let mut modified = false;

        if let Some(acc) = account_name {
            self.account_name = acc;
            modified = true;
        }

        if let Some(user) = username {
            self.username = user;
            modified = true;
        }

        if let Some(pass) = password {
            self.password = pass;
            modified = true;
        }

        if let Some(note) = notes {
            self.notes = note;
            modified = true;
        }

        if modified {
            self.updated_at = Utc::now();
        }
    }
}

/// Top-level plaintext vault container
/// 
/// This structure is serialized and encrypted as a unit
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    /// Schema version for forward compatibility
    pub version: u32,

    /// Stored password entries
    pub entries: Vec<PasswordEntry>,

    /// Vault creation timestamp
    #[zeroize(skip)]
    pub created_at: DateTime<Utc>,

    /// Last vault modification timestamp
    #[zeroize(skip)]
    pub last_modified: DateTime<Utc>,
}

impl Vault {
    /// Current vault schema version
    pub const CURRENT_VERSION: u32 = 1;

    /// Creates an empty vault
    pub fn new() -> Self {
        let now = Utc::now();

        Self {
            version: Self::CURRENT_VERSION,
            entries: Vec::new(),
            created_at: now,
            last_modified: now,
        }
    }

    // Adds a new entry to the vault
    pub fn add_entry(&mut self, entry: PasswordEntry) {
        self.entries.push(entry);
        self.touch();
    }

    /// Removes an entry by index
    pub fn remove_entry(&mut self, index: usize) -> Result<PasswordEntry, VaultError> {
        if index >= self.entries.len() {
            return Err(VaultError::EntryNotFound);
        }

        let removed = self.entries.remove(index);
        self.touch();
        ok(removed)
    }

    /// Updates an entry by index
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

    /// Retrieves an entry by index
    pub fn get_entry(&self, index: usize) -> Option<PasswordEntry> {
        self.entries.get(index)
    }

    /// Case-insensitive search across selected fields
    /// 
    /// This operates on decrypted in-memory data only
    pub fn find_entries(&self, query: &str) -> Vec<&PasswordEntry> {
        let query_lower = query.to_lowercase();

        self.entries
        .iter()
        .filter(|entry| {
            entry.account_name.to_lowercase().contains(&query_lower)
            || entry.username.to_lowercase().contains(&query_lower)
            || entry.notes.to_lowercase().contains(&query_lower)
        })
        .collect()
    }

    /// Updates the vault-level modification timestamp
    fn touch(&mut self) {
        self.last_modified = Utc::now();
    }
}