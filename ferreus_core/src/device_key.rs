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

//! Device-specific secret key for vault binding.
//!
//! A [`DeviceKey`] is a 32-byte secret generated once per device and stored in
//! the device's secure storage (see [`crate::device_store`]). It is mixed into
//! the master key derivation (via HKDF in [`crate::crypto`]) so that a vault
//! file stolen from one device cannot be brute-forced on a different machine
//! without also obtaining this device-bound secret.
//!
//! # Security contract
//! - The key bytes are unconditionally zeroized on drop via [`Zeroize`] /
//!   [`ZeroizeOnDrop`].
//! - No `Clone` or `Copy` is derived; key material must not be duplicated.
//! - The only public accessor ([`DeviceKey::as_bytes`]) returns a reference,
//!   not an owned copy, preventing accidental key exfiltration.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte length of the device-specific secret key (256 bits).
pub const DEVICE_KEY_LEN: usize = 32;

/// Device-specific secret key used to bind a vault to a particular machine.
///
/// Generated once and persisted by [`crate::device_store::DeviceKeyStore`].
/// Combined with the user's master password during key derivation so that an
/// attacker who steals the vault file must also compromise the device secret
/// before any offline brute-force attempt can succeed.
//
// RECOMMENDATION: derive `ZeroizeOnDrop` instead of only `Zeroize` — the
// `#[zeroize(drop)]` attribute from the original code was a proc-macro
// approach that is superseded by the cleaner `ZeroizeOnDrop` derive available
// in zeroize ≥ 1.5. Both have identical runtime behaviour; `ZeroizeOnDrop` is
// the idiomatic current spelling.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKey {
    /// The raw key bytes. Never exposed by value; accessed only via reference.
    pub(crate) key: [u8; DEVICE_KEY_LEN],
}

impl DeviceKey {
    /// Generates a new device key using the OS CSPRNG.
    ///
    /// [`OsRng`] draws from the highest-quality entropy source available on
    /// the target platform (`getrandom` on Linux, `BCryptGenRandom` on Windows,
    /// `SecRandomCopyBytes` on macOS / iOS).
    ///
    /// This should be called exactly **once** per device. Subsequent calls
    /// produce a different key, which would permanently prevent decryption of
    /// any vault previously bound to the old key.
    pub fn generate() -> Self {
        let mut key = [0u8; DEVICE_KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Returns a shared reference to the raw key bytes.
    ///
    /// **Handle with care.** Callers must not copy or serialise this slice.
    /// The reference lifetime is tied to `self`, preventing the key from
    /// outliving the [`DeviceKey`] that owns and zeroizes it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}
