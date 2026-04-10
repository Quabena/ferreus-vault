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

//! Cryptographic engine for FerreusVault
//!
//! Responsibilities:
//! - Master key derivation via Argon2id
//! - Vault encryption/decryption via XChaCha20-Poly1305
//! - Encrypted vault container format
//!
//! Security goals:
//! - No plaintext key persistence
//! - No crypto oracles
//! - Explicit, single-source-of-truth KDF parameters
//! - Audit-friendly design

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::VaultError;
use crate::memory::SecureBytes;

/* --------------- Crypto Constants ---------------------------------------- */

/// Argon2id memory cost in KiB (19 MiB — meets OWASP minimum recommendation).
const ARGON2_M_COST: u32 = 19_456;
/// Argon2id iteration count.
const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism. Fixed at 1 for reproducibility across machines.
const ARGON2_P_COST: u32 = 1;

/// Byte length of the random salt embedded in every vault file.
const SALT_LENGTH: usize = 16;
/// Byte length of the XChaCha20-Poly1305 nonce.
const NONCE_LENGTH: usize = 24;
/// Byte length of the derived symmetric key.
const KEY_LENGTH: usize = 32;

/* --------------- Master Key ---------------------------------------------- */

/// A zeroizing wrapper around a 32-byte symmetric key and its derivation salt.
///
/// # Security
/// - The key bytes are zeroed in memory when this value is dropped.
/// - The salt is stored so that the same key can be re-derived for decryption.
/// - Key material is **never** cloned or copied outside this type.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: Zeroizing<[u8; KEY_LENGTH]>,
    salt: [u8; SALT_LENGTH],
}

impl MasterKey {
    /// Derives a master key from a UTF-8 password and a randomly-chosen salt.
    ///
    /// Uses the canonical [`ARGON2_M_COST`] / [`ARGON2_T_COST`] / [`ARGON2_P_COST`]
    /// parameters. This is the **only** place KDF parameters are defined — both
    /// vault creation and vault loading must call this function to guarantee
    /// encrypt/decrypt symmetry.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if Argon2 parameter construction or
    /// hashing fails.
    pub fn from_password_with_salt(password: &str, salt: &[u8; SALT_LENGTH]) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::CryptoError("Password cannot be empty".into()));
        }

        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(KEY_LENGTH),
        )
        .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);

        argon2
            .hash_password_into(password.as_bytes(), salt.as_ref(), key.as_mut())
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        Ok(Self { key, salt: *salt })
    }

    /// Generates a fresh random salt and derives a key from it.
    ///
    /// Use this when **creating** a new vault. The embedded salt is then stored
    /// in [`EncryptedVault`] so the key can be re-derived on every open.
    pub fn new_from_password(password: &str) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        Self::from_password_with_salt(password, &salt)
    }

    /// Returns a reference to the raw key bytes. Handle with care.
    pub fn key_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    /// Returns the salt used during key derivation.
    pub fn salt(&self) -> &[u8; SALT_LENGTH] {
        &self.salt
    }

    /// Locks key memory pages against being swapped to disk.
    ///
    /// This is a best-effort operation: it succeeds only when the
    /// `secure-memory` Cargo feature is enabled. Callers that require
    /// a hard guarantee should check the feature flag explicitly.
    #[allow(unused_variables)]
    pub fn try_lock_memory(&self) {
        #[cfg(feature = "secure-memory")]
        crate::memory::lock_memory(self.key.as_ptr(), KEY_LENGTH);
    }
}

/* --------------- Encrypted Vault Container -------------------------------- */

/// The on-disk representation of an encrypted vault.
///
/// Contains everything needed to re-derive the key and decrypt the payload:
/// - `version`: forward-compatibility guard
/// - `salt`: passed back to [`MasterKey::from_password_with_salt`]
/// - `nonce`: unique per encryption; never reused
/// - `ciphertext`: AEAD-authenticated payload
#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub version: u32,
    pub salt: [u8; SALT_LENGTH],
    pub nonce: [u8; NONCE_LENGTH],
    pub ciphertext: Vec<u8>,
}

impl EncryptedVault {
    pub const CURRENT_VERSION: u32 = 1;

    /// Encrypts a plaintext byte slice using the provided master key.
    ///
    /// A fresh random nonce is generated for every call, ensuring that
    /// encrypting the same plaintext twice produces distinct ciphertexts.
    pub fn encrypt(plaintext: &[u8], master_key: &MasterKey) -> Result<Self, VaultError> {
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| VaultError::CryptoError("Encryption failed".into()))?;

        Ok(Self {
            version: Self::CURRENT_VERSION,
            salt: *master_key.salt(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypts and authenticates the vault payload.
    ///
    /// Authentication failure and ciphertext corruption are both surfaced as
    /// [`VaultError::CryptoError`] without further detail, preventing
    /// oracle-style information leaks.
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecureBytes, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        let plaintext = cipher
            .decrypt(XNonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| VaultError::CryptoError("Decryption or authentication failed".into()))?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Serialises the container to bytes for writing to disk.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|_| VaultError::SerializationError)
    }

    /// Deserialises a container from bytes read from disk.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(bytes).map_err(|_| VaultError::SerializationError)
    }
}

/* --------------- Password Strength Estimator ------------------------------ */

/// Estimates password entropy as a score from 0 to 100.
///
/// The score is based on Shannon entropy: `length × log₂(charset_size)`.
/// A score above 70 is considered strong for a vault master password.
///
/// # Correctness note
/// Charset size categories are **mutually exclusive** and cumulative:
/// lowercase (26), uppercase (26), digits (10), special characters (33).
/// Each category is counted at most once, regardless of how many characters
/// from that category appear in the password.
pub fn estimate_password_strength(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    let length = password.len() as f64;
    let mut charset: f64 = 0.0;

    if password.chars().any(|c| c.is_ascii_lowercase()) {
        charset += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        charset += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        charset += 10.0;
    }
    // Special characters: printable ASCII that is not alphanumeric.
    if password.chars().any(|c| c.is_ascii_punctuation() || c == ' ') {
        charset += 33.0;
    }

    if charset < 1.0 {
        return 0.0;
    }

    // Normalise against a 128-bit entropy target.
    (length * charset.log2() / 128.0 * 100.0).clamp(0.0, 100.0)
}

/* --------------- Tests ---------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master_key = MasterKey::new_from_password("TestPassword123!").unwrap();
        let plaintext = b"Hello, vault!";
        let container = EncryptedVault::encrypt(plaintext, &master_key).unwrap();

        let salt = *master_key.salt();
        let key2 = MasterKey::from_password_with_salt("TestPassword123!", &salt).unwrap();
        let decrypted = container.decrypt(&key2).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let master_key = MasterKey::new_from_password("CorrectPassword1!").unwrap();
        let container = EncryptedVault::encrypt(b"secret", &master_key).unwrap();

        let salt = *master_key.salt();
        let wrong_key = MasterKey::from_password_with_salt("WrongPassword1!", &salt).unwrap();
        assert!(container.decrypt(&wrong_key).is_err());
    }

    #[test]
    fn password_strength_correctness() {
        // Pure lowercase — charset = 26, not inflated by alphanumeric catch-all.
        let lowercase_score = estimate_password_strength("aaaaaaaaaaaaa");
        // Mixed — should score higher.
        let mixed_score = estimate_password_strength("Abc123!@#defgh");
        assert!(mixed_score > lowercase_score, "mixed should outscore pure lowercase");
        assert!(estimate_password_strength("") == 0.0);
    }

    #[test]
    fn kdf_is_deterministic_with_same_salt() {
        let salt = [0xABu8; SALT_LENGTH];
        let k1 = MasterKey::from_password_with_salt("SamePass1!", &salt).unwrap();
        let k2 = MasterKey::from_password_with_salt("SamePass1!", &salt).unwrap();
        assert_eq!(k1.key_bytes(), k2.key_bytes());
    }
}
