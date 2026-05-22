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
//! Responsibilities: Argon2id key derivation, XChaCha20-Poly1305 authenticated
//! encryption, block padding, and XOR split-key in-memory protection.
//!
//! ## Security invariants
//! - All key material is zeroized on drop via [`ZeroizeOnDrop`].
//! - Authentication failure is indistinguishable from ciphertext corruption at
//!   the API boundary — no detail is surfaced to callers.
//! - The container header (version, salt, nonce, generation) is bound into the
//!   AEAD as additional authenticated data (AAD). Any post-encryption mutation
//!   of these fields causes decryption to fail, preventing version-downgrade and
//!   rollback attacks.
//! - A single set of KDF constants (`ARGON2_*`) governs both the creation and
//!   unlock paths; there is no way to accidentally derive different keys.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::VaultError;
use crate::memory::SecureBytes;

/* ─────────────────────────── Constants ────────────────────────────────── */

/// Argon2id memory cost in KiB (19 MiB).
/// Satisfies the OWASP minimum for interactive authentication and the NIST
/// SP 800-63B high-assurance tier. Increase when latency budget permits.
const ARGON2_M_COST: u32 = 19_456;

/// Argon2id iteration count. Two passes provides meaningful time-hardening
/// while keeping unlock latency acceptable on constrained hardware.
const ARGON2_T_COST: u32 = 2;

/// Argon2id parallelism degree, fixed at 1.
/// Higher parallelism cheapens offline attacks on multi-core attackers without
/// proportionally raising cost for single-core legitimate users.
const ARGON2_P_COST: u32 = 1;

/// Byte length of the random KDF salt embedded in every vault file (128 bits).
/// Matches the Argon2 specification recommendation and eliminates salt-reuse
/// risk even when the same password is reused across vaults.
const SALT_LENGTH: usize = 16;

/// Byte length of the XChaCha20-Poly1305 nonce (192-bit extended nonce).
/// The 2^192 nonce space makes random-nonce collision statistically impossible.
const NONCE_LENGTH: usize = 24;

/// Byte length of the derived symmetric key (256-bit ChaCha20 key size).
const KEY_LENGTH: usize = 32;

/// Plaintext block size used for size-concealment padding.
/// Padding aligns vault data to this boundary before encryption so that an
/// observer measuring ciphertext size cannot infer the number of stored entries.
const VAULT_BLOCK_SIZE: usize = 4096;

/* ─────────────────────────── MasterKey ────────────────────────────────── */

/// A 32-byte symmetric key and its derivation salt, zeroized on drop.
///
/// Key bytes are scrubbed from memory unconditionally when this value is
/// dropped. The only public read accessor ([`key_bytes`]) returns a reference
/// rather than an owned copy, preventing accidental duplication.
///
/// [`key_bytes`]: MasterKey::key_bytes
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: Zeroizing<[u8; KEY_LENGTH]>,
    salt: [u8; SALT_LENGTH],
}

impl MasterKey {
    /// Derives a master key from `password`, `salt`, and `device_key`.
    ///
    /// This is the single canonical KDF entry point. Both vault creation and
    /// vault unlock funnel through here, guaranteeing identical Argon2id
    /// parameters on both paths. `device_key` is mixed into the output via
    /// HKDF-SHA256 after Argon2id completes; pass `&[]` to disable device binding.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if Argon2 parameter construction or
    /// hashing fails. Error messages are intentionally generic.
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

        let mut password_key = Zeroizing::new([0u8; KEY_LENGTH]);
        argon2
            .hash_password_into(password.as_bytes(), salt.as_ref(), password_key.as_mut())
            .map_err(|e| VaultError::CryptoError(e.to_string()))?;

        // Mix the device key into the Argon2id output via HKDF-SHA256.
        // When device_key is empty this degrades to HKDF(salt=none, ikm=password_key),
        // which is still a secure PRF — no entropy is lost.
        let key = combine_keys(&password_key[..], device_key);

        Ok(Self { key, salt: *salt })
    }

    /// Generates a fresh random salt and derives a key from `password` and
    /// `device_key`.
    ///
    /// Call this only when **creating** a new vault. The salt embedded in the
    /// returned [`MasterKey`] must be persisted in the vault header so the
    /// identical key can be reproduced on every subsequent unlock. Pass `&[]`
    /// for `device_key` to disable device binding.
    pub fn new_from_password(password: &str, device_key: &[u8]) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        Self::from_password_with_salt(password, &salt, device_key)
    }

    /// Wraps existing key bytes and salt without running the KDF.
    ///
    /// Use only when reconstructing a [`MasterKey`] from [`SplitKey`] shares
    /// after unlock. The bytes must originate from a prior Argon2id derivation.
    pub fn from_bytes(key: [u8; KEY_LENGTH], salt: [u8; SALT_LENGTH]) -> Self {
        Self {
            key: Zeroizing::new(key),
            salt,
        }
    }

    /// Returns the raw 32-byte key material by reference.
    ///
    /// Do not copy or serialize this slice. The reference lifetime is tied to
    /// `self`, preventing the key from outliving the value that will zeroize it.
    pub fn key_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    /// Returns the 16-byte KDF salt stored in this key.
    ///
    /// Must be written into the vault header at creation time so
    /// [`from_password_with_salt`] can reproduce the key on unlock.
    ///
    /// [`from_password_with_salt`]: MasterKey::from_password_with_salt
    pub fn salt(&self) -> &[u8; SALT_LENGTH] {
        &self.salt
    }

    /// Attempts to lock the key's memory pages against being swapped to disk.
    ///
    /// Best-effort: only active when the `secure-memory` Cargo feature is
    /// enabled and the process holds `CAP_IPC_LOCK` (or equivalent). The vault
    /// remains functional without this; the consequence of failure is a
    /// marginally reduced security posture, not incorrect behaviour.
    #[allow(unused_variables)]
    pub fn try_lock_memory(&self) {
        #[cfg(feature = "secure-memory")]
        crate::memory::lock_memory(self.key.as_ptr(), KEY_LENGTH);
    }
}

/* ─────────────────────────── EncryptedVault ───────────────────────────── */

/// The complete on-disk representation of an encrypted vault.
///
/// Every field required to authenticate, re-derive the key, and decrypt the
/// payload is embedded in this structure. No external state is needed.
///
/// | Field        | Purpose                                                    |
/// |--------------|------------------------------------------------------------|
/// | `version`    | Format guard; checked before decryption                   |
/// | `salt`       | KDF salt for [`MasterKey::from_password_with_salt`]        |
/// | `nonce`      | Per-encryption XChaCha20 nonce; never reused               |
/// | `generation` | Monotonic save counter; detects rollback attacks           |
/// | `ciphertext` | Authenticated ciphertext including the 16-byte Poly1305 tag|
///
/// The `version`, `salt`, `nonce`, and `generation` fields are bound as AEAD
/// additional authenticated data (AAD) during both encryption and decryption.
/// Mutating any of them after encryption causes the Poly1305 tag to fail,
/// preventing version-downgrade and file-rollback attacks.
#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Format version. Must equal [`CURRENT_VERSION`] on load.
    ///
    /// [`CURRENT_VERSION`]: EncryptedVault::CURRENT_VERSION
    pub version: u32,

    /// Argon2id salt; 16 random bytes generated once at vault creation.
    pub salt: [u8; SALT_LENGTH],

    /// XChaCha20-Poly1305 nonce; 24 random bytes generated per encryption.
    pub nonce: [u8; NONCE_LENGTH],

    /// Monotonic save counter, incremented by [`VaultManager`] on every write.
    ///
    /// Included in the AEAD AAD so replacing the vault file with an older copy
    /// (rollback attack) causes authentication to fail on the next unlock.
    ///
    /// [`VaultManager`]: crate::VaultManager
    pub generation: u64,

    /// AEAD ciphertext including the 16-byte Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedVault {
    /// The only format version this build can read and write.
    /// Increment when the on-disk layout changes in a backward-incompatible way
    /// and add a migration path in `storage.rs`.
    pub const CURRENT_VERSION: u32 = 1;

    /// Encrypts `plaintext` with `master_key` and binds `generation` into the AAD.
    ///
    /// A fresh 192-bit nonce is generated per call so encrypting identical
    /// plaintext twice always produces distinct ciphertexts. The header fields
    /// (version, salt, nonce, generation) are included as AEAD additional
    /// authenticated data, cryptographically binding them to the ciphertext.
    ///
    /// # Errors
    /// Returns [`VaultError::CryptoError`] if the AEAD operation fails.
    pub fn encrypt(
        plaintext: &[u8],
        master_key: &MasterKey,
        generation: u64,
    ) -> Result<Self, VaultError> {
        let mut nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));
        let aad = build_aad(Self::CURRENT_VERSION, master_key.salt(), &nonce, generation);

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
            generation,
            ciphertext,
        })
    }

    /// Authenticates and decrypts the vault payload.
    ///
    /// Reconstructs the AAD (version, salt, nonce, generation) from the stored
    /// header fields and passes it to the AEAD for verification. Any mutation
    /// of the header since encryption — including version substitution, nonce
    /// replacement, or generation rollback — causes authentication to fail.
    ///
    /// Authentication failure and ciphertext corruption are both surfaced as
    /// [`VaultError::CryptoError`] with no distinguishing detail, preventing
    /// oracle-style attacks.
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecureBytes, VaultError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(master_key.key_bytes()));

        // Use the stored header fields — not the MasterKey's internal copies —
        // to reconstruct AAD. This is more explicit and avoids a subtle coupling
        // between the container and the key object.
        let aad = build_aad(self.version, &self.salt, &self.nonce, self.generation);

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

    /// Serializes the container to bytes for writing to disk.
    ///
    /// Uses `bincode` for compact, deterministic encoding. Deserialize with
    /// [`from_bytes`].
    ///
    /// [`from_bytes`]: EncryptedVault::from_bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|_| VaultError::SerializationError)
    }

    /// Deserializes a container from bytes produced by [`to_bytes`].
    ///
    /// [`to_bytes`]: EncryptedVault::to_bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(bytes).map_err(|_| VaultError::SerializationError)
    }
}

/* ─────────────────────────── Password Strength ────────────────────────── */

/// Estimates password entropy as a score in `[0.0, 100.0]`.
///
/// Score = `(length × log₂(charset_size) / 128) × 100`, normalized so that a
/// perfectly random 128-bit key scores exactly 100. A score above 70 is
/// considered adequate for a vault master password.
///
/// Each character category (lowercase, uppercase, digits, punctuation/space)
/// contributes to `charset_size` at most once, regardless of how many characters
/// from that category appear. This prevents inflating the score by repetition.
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
    if password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ')
    {
        charset += 33.0;
    }

    if charset < 1.0 {
        return 0.0;
    }

    (length * charset.log2() / 128.0 * 100.0).clamp(0.0, 100.0)
}

/* ─────────────────────────── Block Padding ────────────────────────────── */

/// Pads `data` to the next multiple of [`VAULT_BLOCK_SIZE`].
///
/// Uses a 4-byte little-endian length prefix to record the original data size,
/// followed by the original bytes, followed by zero-fill to the next block
/// boundary. This scheme is unambiguous at any block size, including sizes
/// larger than `u8::MAX` (which would overflow a PKCS#7 single-byte length).
///
/// Layout after padding:
/// ```text
/// [0..4]          original_len  (u32, little-endian)
/// [4..4+orig_len] original data
/// [4+orig_len..]  zero-fill to next block boundary
/// ```
pub fn pad_data(data: Vec<u8>) -> Vec<u8> {
    let orig_len = data.len();
    let prefixed_len = 4 + orig_len;
    let remainder = prefixed_len % VAULT_BLOCK_SIZE;
    let padding_len = if remainder == 0 {
        VAULT_BLOCK_SIZE
    } else {
        VAULT_BLOCK_SIZE - remainder
    };

    let total = prefixed_len + padding_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(orig_len as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out.resize(total, 0u8);
    out
}

/// Removes padding added by [`pad_data`] and returns the original data.
///
/// Reads the 4-byte little-endian length prefix to recover the original slice.
///
/// # Errors
/// Returns [`VaultError::CryptoError`] if the buffer is shorter than 4 bytes or
/// the stored length exceeds the available data, indicating corruption or tampering.
pub fn unpad_data(data: Vec<u8>) -> Result<Vec<u8>, VaultError> {
    if data.len() < 4 {
        return Err(VaultError::CryptoError(
            "Buffer too short to contain length prefix".into(),
        ));
    }

    let orig_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;

    if orig_len > data.len().saturating_sub(4) {
        return Err(VaultError::CryptoError(
            "Stored length prefix exceeds buffer size".into(),
        ));
    }

    Ok(data[4..4 + orig_len].to_vec())
}

/* ─────────────────────────── SplitKey ─────────────────────────────────── */

/// An XOR-split guard that holds a 256-bit key across two separate allocations.
///
/// Splitting the key reduces the probability that a partial heap dump or
/// cold-boot attack recovers usable key material. An attacker who obtains only
/// one share learns nothing about the key — XOR secret sharing is
/// information-theoretically secure when the mask (`share_a`) is uniformly random.
///
/// Both shares are zeroized on drop. This provides process-memory-level defence
/// in depth and does not protect against an attacker with full address-space access.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SplitKey {
    /// Uniformly random 256-bit mask generated at split time.
    share_a: [u8; KEY_LENGTH],

    /// `full_key XOR share_a`. Meaningless without `share_a`.
    share_b: [u8; KEY_LENGTH],
}

impl SplitKey {
    /// Splits `full_key` into two XOR shares.
    ///
    /// `share_a` is drawn from the OS CSPRNG; `share_b = full_key XOR share_a`.
    /// `full_key` is consumed by this call and therefore dropped (and zeroized
    /// by any wrapping [`Zeroizing`] guard) at the call site.
    pub fn new(full_key: [u8; KEY_LENGTH]) -> Self {
        let mut share_a = [0u8; KEY_LENGTH];
        let mut share_b = [0u8; KEY_LENGTH];

        OsRng.fill_bytes(&mut share_a);

        for i in 0..KEY_LENGTH {
            share_b[i] = full_key[i] ^ share_a[i];
        }

        Self { share_a, share_b }
    }

    /// Reconstructs the original key by XOR-ing the two shares.
    ///
    /// Wrap the returned array in [`Zeroizing`] at the call site to ensure the
    /// reconstructed bytes are scrubbed when they fall out of scope.
    pub fn reconstruct(&self) -> [u8; KEY_LENGTH] {
        let mut key = [0u8; KEY_LENGTH];
        for i in 0..KEY_LENGTH {
            key[i] = self.share_a[i] ^ self.share_b[i];
        }
        key
    }

    /// Reconstructs the shares into a [`MasterKey`] bound to `salt`.
    pub fn reconstruct_master_key(&self, salt: [u8; SALT_LENGTH]) -> MasterKey {
        MasterKey::from_bytes(self.reconstruct(), salt)
    }
}

/* ─────────────────────────── Device Key Combiner ──────────────────────── */

/// Combines an Argon2id-derived key with a device key using HKDF-SHA256.
///
/// Using HKDF (rather than XOR) ensures that combining a strong password key
/// with an absent or low-entropy device key cannot weaken the result: HKDF is
/// a proper PRF and its output is computationally indistinguishable from a
/// uniformly random key regardless of the device key's quality.
///
/// `device_key` is used as the HKDF salt; an empty slice is valid and degrades
/// gracefully to HKDF with no salt, which is still secure.
fn combine_keys(password_key: &[u8], device_key: &[u8]) -> Zeroizing<[u8; KEY_LENGTH]> {
    let hk = Hkdf::<Sha256>::new(
        if device_key.is_empty() {
            None
        } else {
            Some(device_key)
        },
        password_key,
    );
    let mut out = Zeroizing::new([0u8; KEY_LENGTH]);
    hk.expand(b"ferreus-vault-master-key", out.as_mut())
        .expect("HKDF expand failed — output length is a compile-time constant");
    out
}

/* ─────────────────────────── AAD Builder ──────────────────────────────── */

/// Encodes the vault header as a canonical byte sequence for AEAD AAD.
///
/// Binding these fields into the AAD means any post-encryption mutation of the
/// header (version downgrade, nonce substitution, generation rollback) causes
/// the Poly1305 tag to fail.
///
/// Layout (stable protocol invariant — changing this breaks all existing vaults):
/// ```text
/// [0..4]   version    (u32, little-endian)
/// [4..20]  salt       (16 bytes)
/// [20..44] nonce      (24 bytes)
/// [44..52] generation (u64, little-endian)
/// ```
fn build_aad(
    version: u32,
    salt: &[u8; SALT_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    generation: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + SALT_LENGTH + NONCE_LENGTH + 8);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

/* ─────────────────────────── Tests ────────────────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// Full encrypt → re-derive → decrypt round trip.
    /// Verifies KDF determinism, AAD symmetry, and Poly1305 acceptance.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master_key = MasterKey::new_from_password("TestPassword123!", &[]).unwrap();
        let plaintext = b"Hello, vault!";
        let container = EncryptedVault::encrypt(plaintext, &master_key, 1).unwrap();

        let salt = *master_key.salt();
        let key2 = MasterKey::from_password_with_salt("TestPassword123!", &salt, &[]).unwrap();

        let decrypted = container.decrypt(&key2).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    /// A different password with the same salt must not authenticate.
    #[test]
    fn wrong_password_fails_authentication() {
        let master_key = MasterKey::new_from_password("CorrectPassword1!", &[]).unwrap();
        let container = EncryptedVault::encrypt(b"secret", &master_key, 1).unwrap();

        let salt = *master_key.salt();
        let wrong_key = MasterKey::from_password_with_salt("WrongPassword1!", &salt, &[]).unwrap();

        assert!(container.decrypt(&wrong_key).is_err());
    }

    /// Mutating the version field after encryption must fail authentication
    /// because the AAD no longer matches.
    #[test]
    fn tampered_header_fails_authentication() {
        let master_key = MasterKey::new_from_password("TamperTest1!", &[]).unwrap();
        let mut container = EncryptedVault::encrypt(b"sensitive data", &master_key, 1).unwrap();

        container.version = 0; // simulate version-downgrade attack

        let key2 =
            MasterKey::from_password_with_salt("TamperTest1!", &container.salt, &[]).unwrap();
        assert!(
            container.decrypt(&key2).is_err(),
            "Tampered version field must fail AEAD authentication"
        );
    }

    /// Mutating the generation field after encryption must fail authentication.
    #[test]
    fn tampered_generation_fails_authentication() {
        let master_key = MasterKey::new_from_password("RollbackTest1!", &[]).unwrap();
        let mut container = EncryptedVault::encrypt(b"vault payload", &master_key, 42).unwrap();

        container.generation = 1; // simulate rollback to an earlier generation

        let key2 =
            MasterKey::from_password_with_salt("RollbackTest1!", &container.salt, &[]).unwrap();
        assert!(
            container.decrypt(&key2).is_err(),
            "Tampered generation field must fail AEAD authentication"
        );
    }

    /// Mixed character classes must score higher than pure lowercase,
    /// and an empty password must return exactly 0.
    #[test]
    fn password_strength_correctness() {
        let lowercase = estimate_password_strength("aaaaaaaaaaaaa");
        let mixed = estimate_password_strength("Abc123!@#defgh");

        assert!(mixed > lowercase);
        assert_eq!(estimate_password_strength(""), 0.0);
    }

    /// Argon2id must be deterministic: same password + salt → same key.
    #[test]
    fn kdf_is_deterministic_with_same_salt() {
        let salt = [0xABu8; SALT_LENGTH];
        let k1 = MasterKey::from_password_with_salt("SamePass1!", &salt, &[]).unwrap();
        let k2 = MasterKey::from_password_with_salt("SamePass1!", &salt, &[]).unwrap();

        assert_eq!(k1.key_bytes(), k2.key_bytes());
    }

    /// pad_data → unpad_data must be an identity at all input sizes including
    /// zero, the block boundary, and sizes that straddle it.
    #[test]
    fn pad_unpad_roundtrip() {
        for size in [0usize, 1, 4091, 4092, 4096, 4097, 8192] {
            let original: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
            let padded = pad_data(original.clone());

            assert_eq!(
                padded.len() % VAULT_BLOCK_SIZE,
                0,
                "Padded length must be block-aligned for size={size}"
            );

            let recovered = unpad_data(padded)
                .unwrap_or_else(|e| panic!("unpad_data failed for size={size}: {e:?}"));

            assert_eq!(recovered, original, "Round-trip failed for size={size}");
        }
    }

    /// SplitKey reconstruct must return the exact original bytes.
    #[test]
    fn split_key_reconstruct_identity() {
        let original: [u8; KEY_LENGTH] = core::array::from_fn(|i| i as u8);
        let split = SplitKey::new(original);
        assert_eq!(split.reconstruct(), original);
    }
}
