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
//! - No accidental leakage of sensitive material in error messages
//! - Clear separation between user-facing errors and internal causes
//! - Consistent conversion from third-party crate errors

use std::io;
use thiserror::Error;

/// All recoverable errors that can occur while using the vault.
///
/// Variants are kept minimal and deliberately generic where appropriate.
/// Cryptographic failure reasons are not propagated to callers to prevent
/// oracle-style information leaks.
#[derive(Error, Debug)]
pub enum VaultError {
    /// A cryptographic operation failed (key derivation, encryption,
    /// authentication tag verification, etc.).
    ///
    /// The message string is **internal** diagnostic context only. It must not
    /// be forwarded verbatim to end users, as it may reveal algorithm-specific
    /// behaviour that aids attacks.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Serialisation or deserialisation of vault data failed.
    ///
    /// Typical causes:
    /// - Corrupted vault file
    /// - Incompatible format version
    /// - Unexpected structural mismatch during bincode decode
    #[error("Vault data could not be serialized or deserialized")]
    SerializationError,

    /// The master password failed authentication.
    ///
    /// Deliberately non-specific to prevent timing and oracle attacks.
    /// Callers must not attempt to distinguish wrong-password from
    /// corrupted-vault at this level — both surface as authentication failure.
    #[error("Invalid password or corrupted vault")]
    InvalidPassword,

    /// The vault file is structurally malformed or its version is unsupported.
    ///
    /// Distinct from [`VaultError::InvalidPassword`]: this indicates the file
    /// itself cannot be parsed, not that authentication failed.
    #[error("Vault file is corrupted or uses an unsupported format version")]
    CorruptedVault,

    /// An underlying file-system or I/O operation failed.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// The requested entry index does not exist in the vault.
    #[error("Entry not found")]
    EntryNotFound,

    /// An operation was attempted while the vault is locked.
    #[error("Vault is locked — unlock before performing this operation")]
    VaultLocked,
}

/* ----- Conversions from external crates ---------------------------------- */

/// Argon2 errors are mapped to a generic cryptographic failure.
///
/// Detailed Argon2 diagnostics are retained in the message string for
/// internal logging but must not be forwarded to end users.
impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self {
        VaultError::CryptoError(format!("key derivation failed: {e}"))
    }
}

/// AEAD errors (wrong key, corrupted ciphertext, truncated tag) are collapsed
/// into a generic cryptographic failure. No detail is propagated.
impl From<chacha20poly1305::Error> for VaultError {
    fn from(_: chacha20poly1305::Error) -> Self {
        VaultError::CryptoError("authenticated decryption failed".into())
    }
}

/// Bincode errors are collapsed into a generic serialisation failure.
/// Internal format details are intentionally discarded.
impl From<Box<bincode::ErrorKind>> for VaultError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        VaultError::SerializationError
    }
}
