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

//! Centralized error definitions for FerreusVault
//!
//! Design goals:
//! - Explicit error taxonomy for auditability
//! - No accidental leakage of sensitive material
//! - Clear separation between user-facing errors and internal causes
//! - Safe zeroization on drop where memory may contain secrets

use std::io;
use thiserror::Error;

/// All recoverable errors that can occur while using the vault.
///
/// This enum is intentionally small and explicit. If an error does not
/// clearly belong here, it likely indicates a design issue upstream.
///
/// All variants are deliberately generic to avoid leaking sensitive
/// implementation details (e.g., cryptographic failure reasons).
#[derive(Error, Debug)]
pub enum VaultError {
    /// Cryptographic failure (key derivation, encryption, authentication).
    ///
    /// The inner cause is intentionally discarded to:
    /// - Prevent oracle-style information leaks
    /// - Avoid exposing algorithm-specific behavior
    #[error("Cryptographic error")]
    CryptoError,

    /// Failure during serialization or deserialization of vault data.
    ///
    /// Typically indicates:
    /// - Corrupted vault file
    /// - Incompatible format version
    /// - Unexpected structural mismatch
    #[error("Serialization error")]
    SerializationError,

    /// The supplied master password failed authentication.
    ///
    /// This error is deliberately non-specific to avoid password oracle leaks.
    #[error("Invalid password")]
    InvalidPassword,

    /// Vault file is malformed, corrupted, or fails authentication.
    #[error("Vault file corrupted or invalid format")]
    CorruptedVault,

    /// Underlying I/O error (file access, permissions, disk issues).
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Requested entry does not exist in the vault.
    #[error("Entry not found")]
    EntryNotFound,

    /// Operation attempted while the vault is locked.
    #[error("Vault is locked")]
    VaultLocked,
}

//
// ----- Conversions from external crates -----
//

/// Convert Argon2 errors into generic cryptographic failure.
///
/// Detailed error messages are intentionally discarded.
impl From<argon2::Error> for VaultError {
    fn from(_: argon2::Error) -> Self {
        VaultError::CryptoError
    }
}

/// Convert AEAD errors into generic cryptographic failure.
///
/// Authentication failures and malformed ciphertext are treated identically.
impl From<chacha20poly1305::Error> for VaultError {
    fn from(_: chacha20poly1305::Error) -> Self {
        VaultError::CryptoError
    }
}

/// Convert bincode serialization errors into generic serialization failure.
///
/// Internal format details are intentionally discarded.
impl From<Box<bincode::ErrorKind>> for VaultError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        VaultError::SerializationError
    }
}
