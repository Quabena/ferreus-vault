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

//! Cryptographic engine for FerreusVault.
//!
//! # Responsibilities
//! - Master key derivation via Argon2id
//! - Vault encryption/decryption via XChaCha20-Poly1305
//! - Encrypted vault container serialisation/deserialisation
//!
//! # Security design goals
//! - No plaintext key persistence in memory beyond this module's controlled types
//! - No crypto oracle — authentication failure is indistinguishable from
//!   ciphertext corruption at the API boundary
//! - Single source of truth for all KDF parameters; both encryption and
//!   decryption paths call the same [`MasterKey::from_password_with_salt`]
//! - All key material is zeroised on drop via the [`Zeroize`] / [`ZeroizeOnDrop`]
//!   derive macros
//!
//! # Correctness invariant
//! [`EncryptedVault::encrypt`] binds the container header (version, salt, nonce)
//! into the AEAD as *additional authenticated data* (AAD). [`EncryptedVault::decrypt`]
//! **must** reconstruct the identical AAD from the stored header fields and pass it
//! to the cipher — failing to do so breaks the authentication guarantee entirely.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::VaultError;
use crate::memory::SecureBytes;

/* ─────────────────────────── Crypto Constants ─────────────────────────── */

/// Argon2id memory cost in KiB (19 MiB — satisfies the OWASP minimum of 19 MiB
/// for interactive authentication and the NIST SP 800-63B high-assurance tier).
const ARGON2_M_COST: u32 = 19_456;

/// Argon2id iteration count (time cost).  Two passes provides meaningful
/// time-hardening while keeping unlock latency acceptable on low-end hardware.
const ARGON2_T_COST: u32 = 2;

/// Argon2id parallelism fixed at 1.  A higher degree of parallelism would make
/// offline attacks cheaper on multi-core machines without proportionally
/// increasing the legitimate user's cost on constrained devices.
const ARGON2_P_COST: u32 = 1;

/// Byte length of the random KDF salt embedded in every vault file.
/// 16 bytes provides 128 bits of salt entropy, matching the Argon2 specification
/// recommendation and eliminating any risk of salt reuse across vaults.
const SALT_LENGTH: usize = 16;

/// Byte length of the XChaCha20-Poly1305 nonce (192-bit extended nonce).
/// The extended nonce space (2^192) makes random nonce reuse statistically
/// impossible even when encrypting billions of vaults.
const NONCE_LENGTH: usize = 24;

/// Byte length of the derived symmetric key (256-bit AES / ChaCha key size).
const KEY_LENGTH: usize = 32;

/* ─────────────────────────── Master Key ───────────────────────────────── */

/// A zeroising wrapper around a 32-byte symmetric key and its derivation salt.
///
/// # Security contract
/// - Key bytes are unconditionally zeroed in memory when this value is dropped,
///   courtesy of [`ZeroizeOnDrop`].
/// - The salt is stored alongside the key so that the same master key can be
///   re-derived during vault unlock without a second password prompt.
/// - Key material **must never** be cloned, copied, or serialised outside this
///   type.  The only public accessor is [`MasterKey::key_bytes`], which returns
///   a reference, not an owned copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    /// The derived 256-bit symmetric key, stored in a [`Zeroizing`] wrapper so
    /// that the stack allocation is also scrubbed when the guard is dropped.
    key: Zeroizing<[u8; KEY_LENGTH]>,

    /// The random 16-byte salt consumed by Argon2id during key derivation.
    /// Stored here so callers can persist it in the [`EncryptedVault`] header
    /// without needing a separate out-parameter.
    salt: [u8; SALT_LENGTH],

    /// Vault Key
    vault_key: Zeroizing<[u8; KEY_LENGTH]>,

    let initial_vault_key = combine_keys(&password_key, device_key);

    Ok(Self {
        key: Zeroizing::new(combined),
        salt: salt.try_into().map_err(|_| VaultError::CryptoError("Invalid salt".into()))?;
        vault_key: Zeroizing::new(initial_vault_key),
    })
}

impl MasterKey {
    /// Derives a master key from a UTF-8 password and an existing salt.
    ///
    /// This is the **canonical** KDF entry point.  Both vault creation
    /// ([`MasterKey::new_from_password`]) and vault unlock must funnel through
    /// here to guarantee that identical KDF parameters are used on both paths —
    /// a mismatch would silently produce a different key and fail authentication.
    ///
    /// # Parameters
    /// - `password` — the user-supplied passphrase; must be non-empty.
    /// - `salt` — a 16-byte value previously produced by
    ///   [`MasterKey::new_from_password`] and stored in the vault header.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if Argon2 parameter construction or
    /// hashing fails.  The error message is intentionally generic to avoid
    /// leaking implementation details.

    pub fn from_password_with_salt(
        password: &str,
        salt: &[u8; SALT_LENGTH],
        device_key: &[u8],
    ) -> Result<Self, VaultError> {
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

        // Zeroized so key material is scrubbed even if combine_keys panics.
        let mut password_key = Zeroizing::new([0u8; KEY_LENGTH]);

        argon2
            .hash_password_into(password.as_bytes(), salt.as_ref(), password_key.as_mut())
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        let combined = combine_keys(&password_key, device_key);

        Ok(Self {
            key: combined,
            salt: *salt,
        })
    }

    /// Generates a fresh cryptographically random salt and derives a key from it.
    ///
    /// Use this when **creating** a new vault.  The salt embedded in the returned
    /// [`MasterKey`] must be stored in the [`EncryptedVault`] header so that the
    /// key can be re-derived on every subsequent unlock.
    ///
    /// # Errors
    /// Propagates errors from [`MasterKey::from_password_with_salt`].
    pub fn new_from_password(password: &str) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LENGTH];

        // OsRng draws from the OS CSPRNG (getrandom on Linux, BCryptGenRandom on
        // Windows).  This is the highest-quality entropy source available and is
        // appropriate for security-critical salts.
        OsRng.fill_bytes(&mut salt);

        Self::from_password_with_salt(password, &salt)
    }

    /// Returns a shared reference to the raw 32-byte key material.
    ///
    /// **Handle with care.**  The caller must not copy or serialise this slice.
    /// The reference lifetime is tied to `self`, preventing the key from
    /// outliving the [`MasterKey`] that owns and zeroes it.
    pub fn key_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    /// Returns the 16-byte salt used during key derivation.
    ///
    /// This value must be written into the vault header during creation so that
    /// [`MasterKey::from_password_with_salt`] can reproduce the identical key on
    /// unlock.
    pub fn salt(&self) -> &[u8; SALT_LENGTH] {
        &self.salt
    }

    /// Attempts to lock the key's memory pages against being swapped to disk.
    ///
    /// This is a best-effort operation that succeeds only when the
    /// `secure-memory` Cargo feature is enabled and the calling process holds
    /// the `CAP_IPC_LOCK` capability (or an equivalent on non-Linux platforms).
    /// Callers that require a hard guarantee should check the feature flag
    /// explicitly and fail closed if it is absent.
    #[allow(unused_variables)]
    pub fn try_lock_memory(&self) {
        #[cfg(feature = "secure-memory")]
        crate::memory::lock_memory(self.key.as_ptr(), KEY_LENGTH);
    }

    /// Constructs a [`MasterKey`] directly from raw key bytes and a known salt.
    ///
    /// Intended for use in conjunction with [`SplitKey::reconstruct_master_key`]
    /// where the key material has been reconstructed from XOR shares rather than
    /// derived from a password.  The provided key bytes must originate from a
    /// prior Argon2id derivation; passing arbitrary bytes constitutes misuse.
    pub fn from_bytes(key: [u8; KEY_LENGTH], salt: [u8; SALT_LENGTH]) -> Self {
        Self {
            key: Zeroizing::new(key),
            salt,
        }
    }

    pub fn rotate_vault_key(&mut self) {
        let next = ratchet_key(self.vault_key.as_ref());
        self.vault_key.zeroize();
        self.vault_key.copy_from_slice(&next);
    }

    pub fn vault_key_bytes(&self) -> &[u8] {
        &self.vault_key
    }
}

/* ─────────────────────────── Encrypted Vault Container ────────────────── */

/// The on-disk representation of an encrypted vault.
///
/// This structure is the complete, self-contained unit persisted to storage.
/// It embeds every field required to re-derive the master key and authenticate
/// + decrypt the payload:
///
/// | Field        | Purpose                                                  |
/// |--------------|----------------------------------------------------------|
/// | `version`    | Forward-compatibility guard; checked before decryption   |
/// | `salt`       | KDF salt, passed to [`MasterKey::from_password_with_salt`]|
/// | `nonce`      | Unique-per-encryption XChaCha20 nonce; never reused      |
/// | `ciphertext` | AEAD-authenticated ciphertext (payload + 16-byte MAC tag)|
///
/// ## AAD binding
/// The `version`, `salt`, and `nonce` fields are encoded as *additional
/// authenticated data* (AAD) and fed into the AEAD during both encryption and
/// decryption.  This cryptographically binds the header to the ciphertext:
/// any in-place modification of the header (e.g., a version-downgrade attack
/// or a nonce substitution) causes authentication to fail.
#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Format version; must equal [`EncryptedVault::CURRENT_VERSION`].
    pub version: u32,

    /// Argon2id salt; 16 random bytes generated at vault creation time.
    pub salt: [u8; SALT_LENGTH],

    /// XChaCha20-Poly1305 nonce; 24 random bytes generated per encryption.
    pub nonce: [u8; NONCE_LENGTH],

    /// Generation:
    pub generation: u64,

    /// AEAD ciphertext including the 16-byte Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedVault {
    /// The only vault format version this build can read and write.
    /// Increment this constant when the on-disk layout changes in a
    /// backward-incompatible way.
    pub const CURRENT_VERSION: u32 = 1;

    /// Encrypts a plaintext byte slice using the provided master key.
    ///
    /// A fresh 192-bit random nonce is generated for every call, ensuring that
    /// encrypting the same plaintext twice produces distinct ciphertexts.  The
    /// container header (version, salt, nonce) is bound as AAD so that it
    /// cannot be tampered with post-encryption without triggering an
    /// authentication failure on the next open.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if the underlying cipher fails.
    /// In practice this should never occur for valid key material and a
    /// functioning OS RNG.
    pub fn encrypt(plaintext: &[u8], master_key: &MasterKey) -> Result<Self, VaultError> {
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        // Bind version + salt + nonce into the AEAD as authenticated additional
        // data.  This prevents an attacker from substituting a forged header
        // (e.g., a lower version number to trigger a downgrade path) while
        // leaving the ciphertext intact.
        let aad = build_aad(Self::CURRENT_VERSION, master_key.salt(), &nonce);

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::CryptoError("Encryption failed".into()))?;

        Ok(Self {
            version: Self::CURRENT_VERSION,
            salt: *master_key.salt(),
            nonce,
            ciphertext,
        })
    }

    /// Decrypts and authenticates the vault payload using the provided master key.
    ///
    /// The header fields (version, salt, nonce) are re-encoded as AAD and
    /// submitted to the AEAD for verification.  Any mutation of the header
    /// between encryption and decryption — including version substitution or
    /// nonce tampering — will cause authentication to fail here.
    ///
    /// Both authentication failure and ciphertext corruption are surfaced as a
    /// single opaque [`VaultError::CryptoError`] variant.  No further detail is
    /// provided to avoid leaking information to an oracle-style attacker.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if authentication or decryption fails
    /// for any reason.
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecureBytes, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        // CRITICAL: Reconstruct the exact same AAD that was used during encryption.
        // The stored `self.salt` and `self.nonce` fields are the canonical source
        // of truth — the master key's internal salt is NOT used here because by
        // the time decrypt is called, the MasterKey was re-derived from the stored
        // salt, making them identical.  Using `self.salt` is more explicit and
        // avoids a subtle coupling between the key and the container.
        //
        // BUG (fixed): The original code passed `self.ciphertext.as_ref()` as a
        // bare `&[u8]` instead of a `Payload { msg, aad }`.  This silently omitted
        // AAD verification, meaning a tampered header (version, salt, nonce) would
        // pass authentication.
        let aad = build_aad(self.version, &self.salt, &self.nonce);

        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: self.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::CryptoError("Decryption or authentication failed".into()))?;

        Ok(Zeroizing::new(plaintext))
    }

    /// Serialises the container to a byte vector for writing to disk.
    ///
    /// Uses `bincode` for compact, deterministic binary encoding.  The resulting
    /// bytes are opaque and should not be parsed by callers; use
    /// [`EncryptedVault::from_bytes`] for round-trip deserialisation.
    ///
    /// # Errors
    /// Returns [`VaultError::SerializationError`] if bincode serialisation fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|_| VaultError::SerializationError)
    }

    /// Deserialises a container from bytes previously produced by
    /// [`EncryptedVault::to_bytes`].
    ///
    /// # Errors
    /// Returns [`VaultError::SerializationError`] if the bytes are malformed or
    /// do not represent a valid [`EncryptedVault`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(bytes).map_err(|_| VaultError::SerializationError)
    }
}

/* ─────────────────────────── Password Strength Estimator ──────────────── */

/// Estimates password entropy as a score in the range `[0.0, 100.0]`.
///
/// The score is derived from Shannon entropy: `length × log₂(charset_size)`,
/// normalised against a 128-bit entropy target.  A score above 70 is considered
/// adequate for a vault master password.
///
/// ## Charset categories (mutually exclusive, cumulative)
/// | Category        | Symbol space |
/// |-----------------|-------------|
/// | ASCII lowercase | 26          |
/// | ASCII uppercase | 26          |
/// | ASCII digits    | 10          |
/// | ASCII punctuation + space | 33 |
///
/// Each category contributes to `charset_size` at most once, regardless of how
/// many characters from that category appear in the password.  This prevents
/// artificially inflating the score by repeating characters.
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
    // Printable ASCII that is neither alphanumeric nor a control character.
    if password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ')
    {
        charset += 33.0;
    }

    if charset < 1.0 {
        return 0.0;
    }

    // Normalise: a perfectly random 128-bit key maps to a score of 100.
    (length * charset.log2() / 128.0 * 100.0).clamp(0.0, 100.0)
}

/* ─────────────────────────── Block Padding ────────────────────────────── */

/// Block size used for plaintext padding before encryption.
/// Padding conceals the exact size of the vault data from an observer who can
/// measure ciphertext length.
const VAULT_BLOCK_SIZE: usize = 4096;

/// Pads `data` to the next multiple of [`VAULT_BLOCK_SIZE`] using PKCS#7-style
/// padding.
///
/// Each padding byte contains the total number of padding bytes added, making
/// the padding scheme unambiguous and invertible.  For example, if 3 bytes of
/// padding are needed, all 3 padding bytes will contain the value `0x03`.
///
/// If `data` is already a multiple of [`VAULT_BLOCK_SIZE`], one full block of
/// padding (4096 bytes, each `0x00` representing 4096 mod 256 — see note) is
/// appended.  This prevents a zero-padding ambiguity where an unpadded message
/// ending in `0x01` would be misinterpreted as a single padding byte.
///
/// # Note on large block sizes
/// [`VAULT_BLOCK_SIZE`] (4096) exceeds `u8::MAX` (255), so the padding byte
/// value wraps modulo 256.  Callers implementing [`unpad_data`] must account
/// for this by storing the full `usize` padding length in a leading length
/// prefix rather than relying on the byte value alone.  For future-proofing,
/// consider embedding a `u32` little-endian length prefix in the first 4 bytes.
///
/// # See also
/// [`unpad_data`] for the inverse operation.
pub fn pad_data(mut data: Vec<u8>) -> Vec<u8> {
    // Calculate bytes needed to reach the next block boundary.  If already
    // aligned, pad a full block to eliminate the zero-length-padding ambiguity.
    let remainder = data.len() % VAULT_BLOCK_SIZE;
    let padding_len = if remainder == 0 {
        VAULT_BLOCK_SIZE
    } else {
        VAULT_BLOCK_SIZE - remainder
    };

    // Use the low byte of padding_len as the fill value (PKCS#7 convention).
    // See the doc-comment note above regarding block sizes > 255.
    let fill_byte = (padding_len & 0xFF) as u8;
    data.extend(vec![fill_byte; padding_len]);
    data
}

/// Removes padding added by [`pad_data`] from a decrypted plaintext buffer.
///
/// Reads the last byte of `data` to determine the padding fill value, then
/// validates that the terminal `n` bytes all carry that value before truncating.
///
/// # Errors
/// Returns [`VaultError::CryptoError`] if the padding is malformed (e.g., the
/// buffer is shorter than the indicated padding length, or the padding bytes are
/// inconsistent), which may indicate data corruption or tampering.
pub fn unpad_data(data: Vec<u8>) -> Result<Vec<u8>, VaultError> {
    if data.is_empty() {
        return Err(VaultError::CryptoError("Cannot unpad empty buffer".into()));
    }

    // The last byte encodes the padding length (modulo 256).
    let pad_byte = *data.last().unwrap() as usize;

    // A fill value of 0 represents a full block of padding (256 bytes in PKCS#7,
    // or VAULT_BLOCK_SIZE bytes by our convention).
    let padding_len = if pad_byte == 0 {
        VAULT_BLOCK_SIZE
    } else {
        pad_byte
    };

    if data.len() < padding_len {
        return Err(VaultError::CryptoError(
            "Padding length exceeds data length".into(),
        ));
    }

    // Verify all padding bytes to detect corruption or tampering.
    let payload_end = data.len() - padding_len;
    if data[payload_end..].iter().any(|&b| b as usize != pad_byte) {
        return Err(VaultError::CryptoError("Invalid padding bytes".into()));
    }

    Ok(data[..payload_end].to_vec())
}

/* ─────────────────────────── Split Key Protection ─────────────────────── */

/// An XOR-based key-split guard that holds a 256-bit key in two separate shares.
///
/// Splitting the key across two independently zeroised allocations reduces the
/// probability that a partial heap dump or cold-boot attack recovers the full
/// key material.  An attacker who obtains only one share learns nothing about
/// the key — XOR secret sharing is information-theoretically secure when the
/// mask (`share_a`) is uniformly random.
///
/// # Limitations
/// This provides defence-in-depth at the process-memory level only.  It does
/// not protect against an attacker who has read access to the entire process
/// address space simultaneously.
///
/// # Security
/// Both shares are zeroised on drop via [`ZeroizeOnDrop`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SplitKey {
    /// A uniformly random 256-bit mask generated at split time.
    share_a: [u8; KEY_LENGTH],

    /// `full_key XOR share_a`; meaningless without `share_a`.
    share_b: [u8; KEY_LENGTH],
}

impl SplitKey {
    /// Splits `full_key` into two XOR shares and erases the original.
    ///
    /// `share_a` is drawn from the OS CSPRNG; `share_b` is derived as
    /// `full_key[i] ^ share_a[i]` for each byte position.  `full_key` is
    /// moved into this function and therefore dropped (zeroed by the caller's
    /// [`Zeroizing`] wrapper, if present) after the split.
    pub fn new(full_key: [u8; KEY_LENGTH]) -> Self {
        let mut share_a = [0u8; KEY_LENGTH];
        let mut share_b = [0u8; KEY_LENGTH];

        OsRng.fill_bytes(&mut share_a);

        for i in 0..KEY_LENGTH {
            share_b[i] = full_key[i] ^ share_a[i];
        }

        Self { share_a, share_b }
    }

    /// Reconstructs the original 256-bit key by XOR-ing the two shares.
    ///
    /// The caller is responsible for zeroising the returned array after use.
    /// Consider wrapping the return value in [`Zeroizing`] at the call site.
    pub fn reconstruct(&self) -> [u8; KEY_LENGTH] {
        let mut key = [0u8; KEY_LENGTH];

        for i in 0..KEY_LENGTH {
            key[i] = self.share_a[i] ^ self.share_b[i];
        }

        key
    }

    /// Reconstructs the key shares into a [`MasterKey`] bound to `salt`.
    ///
    /// Intended for use after a vault unlock that sourced key material from
    /// split shares rather than a direct Argon2id derivation.
    pub fn reconstruct_master_key(&self, salt: [u8; SALT_LENGTH]) -> MasterKey {
        let key_bytes = self.reconstruct();
        MasterKey::from_bytes(key_bytes, salt)
    }
}

/* ─────────────────────────── AAD Builder ──────────────────────────────── */

/// Serialises the vault container header into a canonical byte sequence for
/// use as AEAD additional authenticated data (AAD).
///
/// The AAD binds the on-disk header (version, salt, nonce) to the ciphertext:
/// any post-encryption mutation of these fields — including a version-downgrade
/// attempt — causes the Poly1305 authentication tag to fail verification.
///
/// # Layout
/// ```text
/// [0..4]    version  (u32, little-endian)
/// [4..20]   salt     (16 bytes, verbatim)
/// [20..44]  nonce    (24 bytes, verbatim)
/// ```
///
/// This layout is a **stable protocol invariant** — changing it in any way
/// renders all existing vault files undecryptable.
fn build_aad(version: u32, salt: &[u8; SALT_LENGTH], nonce: &[u8; NONCE_LENGTH]) -> Vec<u8> {
    // Pre-allocate the exact capacity: 4 (version) + 16 (salt) + 24 (nonce).
    let mut aad = Vec::with_capacity(4 + SALT_LENGTH + NONCE_LENGTH);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

/* ----------------- hkdf key combiner -------------------- */
fn combine_keys(password_key: &[u8], device_key: &[u8]) -> Zeroizing<[u8; KEY_LENGTH]> {
    let hk = Hkdf::<Sha256>::new(Some(device_key), password_key);

    let mut out = Zeroizing::new([0u8; KEY_LENGTH]);
    hk.expand(b"ferreus-vault-master-key", out.as_mut())
        .expect("HKDF expand failed — output length is a compile-time constant");

    out
}

/* ----------------------- Key Ratchet Function ------------------------- */
pub fn ratchet_key(current_key: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, current_key);

    let mut next = [0u8];

    hk.expand(b"ferreus-vault-ratchet", &mut next)
        .expect("HKDF expand failed");

    next
}

/* ─────────────────────────── Tests ────────────────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the basic encrypt → re-derive-key → decrypt round trip.
    /// A successful round trip proves that:
    /// 1. Argon2id is deterministic given the same password + salt.
    /// 2. The AAD is constructed identically on both paths.
    /// 3. Poly1305 authentication passes for an unmodified ciphertext.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master_key = MasterKey::new_from_password("TestPassword123!").unwrap();
        let plaintext = b"Hello, vault!";
        let container = EncryptedVault::encrypt(plaintext, &master_key).unwrap();

        // Simulate vault unlock: re-derive key from the stored salt.
        let salt = *master_key.salt();
        let key2 = MasterKey::from_password_with_salt("TestPassword123!", &salt).unwrap();

        let decrypted = container.decrypt(&key2).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// Confirms that the AEAD tag correctly rejects a key derived from a
    /// different password, even when the salt is identical.
    #[test]
    fn wrong_password_fails_authentication() {
        let master_key = MasterKey::new_from_password("CorrectPassword1!").unwrap();
        let container = EncryptedVault::encrypt(b"secret", &master_key).unwrap();

        let salt = *master_key.salt();
        let wrong_key = MasterKey::from_password_with_salt("WrongPassword1!", &salt).unwrap();

        assert!(container.decrypt(&wrong_key).is_err());
    }

    /// Confirms that header tampering is detected — the AAD binding must
    /// cause authentication to fail when the stored version is mutated.
    #[test]
    fn tampered_header_fails_authentication() {
        let master_key = MasterKey::new_from_password("TamperTest1!").unwrap();
        let mut container = EncryptedVault::encrypt(b"sensitive data", &master_key).unwrap();

        // Simulate a version-downgrade attack by altering the version field
        // after encryption.  Without AAD, this would go undetected.
        container.version = 0;

        // Re-derive the key from the (unmodified) salt — correct password,
        // correct salt, but the header no longer matches the AAD used at
        // encrypt time, so authentication must fail.
        let key2 = MasterKey::from_password_with_salt("TamperTest1!", &container.salt).unwrap();
        assert!(
            container.decrypt(&key2).is_err(),
            "Tampered version field should fail AEAD authentication"
        );
    }

    /// Verifies that the password strength estimator ranks mixed-character
    /// passwords above single-category passwords, and that an empty password
    /// returns exactly 0.
    #[test]
    fn password_strength_correctness() {
        // Pure lowercase — charset = 26.
        let lowercase_score = estimate_password_strength("aaaaaaaaaaaaa");
        // Mixed character classes — should score higher.
        let mixed_score = estimate_password_strength("Abc123!@#defgh");

        assert!(
            mixed_score > lowercase_score,
            "Mixed character classes should outscore pure lowercase"
        );
        assert_eq!(estimate_password_strength(""), 0.0);
    }

    /// Verifies that Argon2id is deterministic: identical password + salt
    /// must always produce the identical key.
    #[test]
    fn kdf_is_deterministic_with_same_salt() {
        let salt = [0xABu8; SALT_LENGTH];
        let k1 = MasterKey::from_password_with_salt("SamePass1!", &salt).unwrap();
        let k2 = MasterKey::from_password_with_salt("SamePass1!", &salt).unwrap();

        assert_eq!(
            k1.key_bytes(),
            k2.key_bytes(),
            "Argon2id must be deterministic for a fixed password and salt"
        );
    }

    /// Verifies the pad → unpad round trip produces the original data
    /// at varying input sizes, including the boundary case where the input
    /// is already block-aligned.
    #[test]
    fn pad_unpad_roundtrip() {
        for size in [0usize, 1, 4095, 4096, 4097, 8192] {
            let original: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            let padded = pad_data(original.clone());

            assert_eq!(
                padded.len() % VAULT_BLOCK_SIZE,
                0,
                "Padded length must be a multiple of VAULT_BLOCK_SIZE for size={size}"
            );

            let recovered = unpad_data(padded)
                .unwrap_or_else(|e| panic!("unpad_data failed for size={size}: {e:?}"));

            assert_eq!(
                recovered, original,
                "Recovered data must match original for size={size}"
            );
        }
    }

    /// Confirms that [`SplitKey`] round-trips through split and reconstruct
    /// without corrupting the key material.
    #[test]
    fn split_key_reconstruct_identity() {
        let original: [u8; KEY_LENGTH] = core::array::from_fn(|i| i as u8);
        let split = SplitKey::new(original);
        let recovered = split.reconstruct();

        assert_eq!(
            recovered, original,
            "Reconstructed key must match the original"
        );
    }
}
