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
//! - Explicit parameter discipline
//! - Audit-friendly design

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::VaultError;
use crate::memory::SecureBytes;

/* --------------- Crypto Constants ---------------- */

const ARGON2_M_COST: u32 = 19_456; // 19MB
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;

/* --------------- Master Key ---------------- */

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: Zeroizing<[u8; KEY_LENGTH]>,
    salt: [u8; SALT_LENGTH],
}

impl MasterKey {
    /// Derives a master key from password using Argon2id
    pub fn from_password(password: &str) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);

        Self::from_password_with_salt(password, &salt)
    }

    /// Derives a master key from password using provided salt
    pub fn from_password_with_salt(password: &str, salt: &[u8]) -> Result<Self, VaultError> {
        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(KEY_LENGTH),
        )?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);

        argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;

        Ok(Self {
            key,
            salt: salt.try_into().map_err(|_| VaultError::CryptoError)?,
        })
    }

    pub fn key_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    pub fn salt(&self) -> &[u8; SALT_LENGTH] {
        &self.salt
    }
}

/* --------------- Encrypted Vault Container ---------------- */

#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub version: u32,
    pub salt: [u8; SALT_LENGTH],
    pub nonce: [u8; NONCE_LENGTH],
    pub ciphertext: Vec<u8>,
}

impl EncryptedVault {
    pub const CURRENT_VERSION: u32 = 1;

    /// Encrypt serialized vault data
    pub fn encrypt(plaintext: &[u8], master_key: &MasterKey) -> Result<Self, VaultError> {
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext)?;

        Ok(Self {
            version: Self::CURRENT_VERSION,
            salt: *master_key.salt(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypt vault payload
    ///
    /// Authentication failure is treated generically

    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecureBytes, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        let plaintext =
            cipher.decrypt(XNonce::from_slice(&self.nonce), self.ciphertext.as_ref())?;

        ok(Zeroizing::new(plaintext))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        Ok(bincode::deserialize(bytes)?)
    }
}

/*--------------------- Password Strength Estimator --------------- */
/// Estimates password entropy strength
/// Returns score 0-100
pub fn estimate_password_strength(password: &str) -> f64 {
    let length = password.len() as f64;

    let mut charset = 0.0;

    if password.chars().any(|c| c.is_lowercase()) {
        charset += 26.0;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        charset += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        charset += 10.0;
    }
    if password.chars().any(|c| c.is_alphanumeric()) {
        charset += 33.0;
    }

    let entropy = length * charset.log2();

    (entropy / 128.0 * 100.0).clamp(0.0, 100.0)
}
