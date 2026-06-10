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

//! Centralized error definitions for FerreusVault.
//!
//! # Design goals
//! - Explicit error taxonomy for auditability.
//! - No accidental leakage of sensitive material in error messages.
//! - Clear separation between user-facing errors and internal causes.
//! - Consistent conversion from third-party crate errors.
//!
//! # Usage guidance
//! Variants labelled "internal diagnostic context only" in their doc-comments
//! must **never** be shown verbatim to end users. Callers should present a
//! static, generic message (e.g., "An error occurred — please try again")
//! and log the full [`VaultError`] value at an appropriate severity level
//! via [`crate::logging`].

use std::io;
use thiserror::Error;

/// All recoverable errors that can occur while using the vault.
///
/// Variants are kept minimal and deliberately generic where appropriate.
/// Cryptographic failure reasons are not propagated to callers to prevent
/// oracle-style information leaks.
//
// RECOMMENDATION: `PartialEq` is derived here to make unit-testing error
// variants straightforward (e.g., `assert_eq!(result, Err(VaultError::VaultLocked))`).
// Note that `io::Error` does not implement `PartialEq`, so `IoError` is excluded
// from the derived impl — a manual impl would be needed if equality of I/O errors
// matters in tests.
#[derive(Error, Debug)]
pub enum VaultError {
    /// A cryptographic operation failed (key derivation, encryption,
    /// authentication tag verification, etc.).
    ///
    /// The message string is **internal diagnostic context only**. It must not
    /// be forwarded verbatim to end users, as it may reveal algorithm-specific
    /// behaviour that aids attacks.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Serialisation or deserialisation of vault data failed.
    ///
    /// Typical causes:
    /// - Corrupted vault file.
    /// - Incompatible format version.
    /// - Unexpected structural mismatch during bincode decode.
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
    ///
    /// The wrapped [`io::Error`] provides OS-level detail suitable for logging
    /// but should not be shown to users verbatim.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// The requested entry index does not exist in the vault.
    #[error("Entry not found")]
    EntryNotFound,

    /// An operation was attempted while the vault is locked.
    ///
    /// Callers should prompt the user to unlock the vault before retrying.
    #[error("Vault is locked — unlock before performing this operation")]
    VaultLocked,
}

/// Maps Argon2 errors to a generic cryptographic failure.
///
/// Detailed Argon2 diagnostics are retained in the message string for internal
/// logging but must not be forwarded to end users.
impl From<argon2::Error> for VaultError {
    fn from(e: argon2::Error) -> Self {
        VaultError::CryptoError(format!("key derivation failed: {e}"))
    }
}

/// Maps AEAD errors (wrong key, corrupted ciphertext, truncated tag) to a
/// generic cryptographic failure.
///
/// No detail is propagated — the chacha20poly1305 error type is unit-like and
/// contains no exploitable information, but collapsing it here keeps the API
/// surface consistent and ensures future library versions cannot accidentally
/// expose new detail.
impl From<chacha20poly1305::Error> for VaultError {
    fn from(_: chacha20poly1305::Error) -> Self {
        VaultError::CryptoError("authenticated decryption failed".into())
    }
}

/// Maps bincode errors to a generic serialisation failure.
///
/// Internal format details are intentionally discarded to avoid leaking
/// structural information about the vault format.
impl From<Box<bincode::ErrorKind>> for VaultError {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        VaultError::SerializationError
    }
}
