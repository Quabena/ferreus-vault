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
//! - Automatic zeroization of secrets on drop via the `zeroize` crate
//! - Cryptographically secure randomness from the OS CSPRNG
//! - Constant-time comparison to prevent timing side-channel leaks
//! - Optional OS-level memory locking (mlock/VirtualLock) behind a feature flag

#[cfg(feature = "secure-memory")]
use crate::memory_lock::LockedMemory;
use rand::distributions::Alphanumeric;
use rand::RngCore;
use rand::{rngs::OsRng, Rng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Secure container for a sensitive UTF-8 string.
///
/// Memory is zeroized automatically when the value is dropped.
pub type SecureString = Zeroizing<String>;

/// Secure container for a sensitive byte buffer.
///
/// Memory is zeroized automatically when the value is dropped.
pub type SecureBytes = Zeroizing<Vec<u8>>;

/// A heap-allocated byte buffer that is zeroized on drop and, when the
/// `secure-memory` feature is enabled, pinned against being swapped to disk.
pub struct SecureBuffer {
    data: Zeroizing<Vec<u8>>,
    /// Holds the `mlock`/`VirtualLock` RAII guard, if acquired.
    #[cfg(feature = "secure-memory")]
    _lock: Option<LockedMemory>,
}

impl SecureBuffer {
    /// Creates a `SecureBuffer` from a plaintext `Vec<u8>`.
    ///
    /// With the `secure-memory` feature enabled, the buffer is locked into
    /// physical RAM before being wrapped in `Zeroizing`. The lock guard and
    /// the data vector are stored together so the unlock happens before the
    /// memory is released.
    pub fn new(data: Vec<u8>) -> Self {
        // Acquire the mlock BEFORE moving data into Zeroizing, so that
        // the locked address matches the address of the live allocation.
        #[cfg(feature = "secure-memory")]
        let lock = LockedMemory::lock(&mut data).ok();

        Self {
            data: Zeroizing::new(data),
            #[cfg(feature = "secure-memory")]
            _lock: lock,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Generates a cryptographically secure random alphanumeric string of `length`
/// characters.
///
/// Uses [`OsRng`] to ensure randomness originates from the operating system
/// CSPRNG. The result is wrapped in a [`SecureString`] and zeroized on drop.
///
/// # Security notes
/// - Intended for session tokens and generated passwords.
/// - Do **not** use this for raw key material — use
///   [`generate_secure_random_bytes`] instead.
pub fn generate_secure_random_string(length: usize) -> SecureString {
    let random_string: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();

    SecureString::new(random_string)
}

/// Generates `length` cryptographically secure random bytes.
///
/// Preferred for cryptographic key material. Uses [`OsRng`] directly.
pub fn generate_secure_random_bytes(length: usize) -> SecureBytes {
    let mut buffer = vec![0u8; length];
    OsRng.fill_bytes(&mut buffer);
    SecureBytes::new(buffer)
}

/// Compares two byte slices in constant time.
///
/// Prevents timing attacks by ensuring execution time does not depend on the
/// data values. Safe to use for comparing authentication tags, derived keys,
/// and similar secrets.
///
/// Returns `false` if the slices have different lengths.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/* ------------------- OS Memory Locking ----------------------------------- */

/// Locks the memory region at `ptr` of `len` bytes against swapping.
///
/// This is a best-effort operation. Failures are silently ignored because
/// the application can still function without memory locking — the
/// consequence of failure is a slightly reduced security posture, not
/// incorrect behaviour.
///
/// Only available when the `secure-memory` Cargo feature is enabled.
#[cfg(feature = "secure-memory")]
pub fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        // Ignore the return value intentionally; mlock failure is non-fatal.
        let _ = libc::mlock(ptr as *const libc::c_void, len);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Memory::VirtualLock;
        let _ = VirtualLock(ptr as *mut _, len);
    }
}

/// Unlocks a previously-locked memory region.
///
/// Only available when the `secure-memory` Cargo feature is enabled.
#[cfg(feature = "secure-memory")]
pub fn unlock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        let _ = VirtualUnlock(ptr as *mut _, len);
    }
}

/* ------------------- Tests ----------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_string_length_and_charset() {
        let s = generate_secure_random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn random_bytes_length() {
        let b = generate_secure_random_bytes(64);
        assert_eq!(b.len(), 64);
    }

    #[test]
    fn constant_time_compare_equal_and_unequal() {
        assert!(constant_time_compare(b"secret", b"secret"));
        assert!(!constant_time_compare(b"secret", b"Secret"));
        assert!(!constant_time_compare(b"short", b"longer"));
    }
}
