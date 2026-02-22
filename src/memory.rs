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

//! Secure memory utilities for handling sensitive data
//!
//! Security goals:
//! - Automatic zeroization of secrets
//! - Use OS-backed cryptographically secure randomness
//! - Avoid timing side-channel leaks
//! - Provide explicit types for material

use rand::distributions::Alphanumeric;
use rand::RngCore;
use rand::{rngs::OsRng, Rng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Secure container for sensitive UTF-8 string data.
///
/// Automatically zeroize memory when dropped.
pub type SecureString = Zeroizing<String>;

/// Secure container for sensitive byte buffers
///
/// Automatically zeroizes memory when dropped
pub type SecureBytes = Zeroizing<Vec<u8>>;

/// Generates a cryptographic secure random alphanumeric string.
///
/// Use `OsRng` to ensure randomness originates from the operating system CSPRNG
///
/// # Security NOtes:
/// - Intended for temporary secrets, tokens, or generated passwords
/// - Avoid using this for key material (use raw bytes instead)
pub fn generate_secure_random_string(length: usize) -> SecureString {
    let mut rng = OsRng;

    let random_string: String = rng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    SecureString::new(random_string)
}

/// Generates cryptographically secure random bytes
///
/// Preferred for cryptographic key material
pub fn generate_secure_random_bytes(length: usize) -> SecureBytes {
    let mut rng = OsRng;
    let mut buffer = vec![0u8; length];

    rng.fill_bytes(&mut buffer);

    SecureBytes::new(buffer)
}

/// Constant time comparison of two byte slices
///
/// Prevents timing attacks by ensuring execution time does not depend on data
///
/// Security Notes:
/// - Safe for comparing authentication tags, derived keys, etc.
/// - Returns `false` if lengths differ
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
