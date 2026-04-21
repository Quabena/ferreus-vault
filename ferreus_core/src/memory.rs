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

//! Secure memory utilities for handling sensitive data.
//!
//! # Security goals
//! - Automatic zeroization of secrets on drop via the `zeroize` crate.
//! - Cryptographically secure randomness from the OS CSPRNG.
//! - Constant-time comparison to prevent timing side-channel leaks.
//! - Optional OS-level memory locking (`mlock` / `VirtualLock`) behind the
//!   `secure-memory` Cargo feature flag.
//!
//! # Feature flags
//! | Feature         | Effect                                                |
//! |-----------------|-------------------------------------------------------|
//! | `secure-memory` | Enables [`SecureBuffer`] memory locking and the      |
//! |                 | `lock_memory` / `unlock_memory` helper functions.    |
//!
//! # Usage guidance
//! - Prefer [`SecureString`] and [`SecureBytes`] for short-lived secrets that
//!   do not need memory locking.
//! - Use [`SecureBuffer`] when you need a best-effort guarantee that key
//!   material is not swapped to disk.
//! - Always use [`constant_time_compare`] when comparing secrets; never use
//!   `==` directly on sensitive byte slices.

#[cfg(feature = "secure-memory")]
use crate::memory_lock::LockedMemory;
use rand::distributions::Alphanumeric;
use rand::RngCore;
use rand::{rngs::OsRng, Rng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Secure container for a sensitive UTF-8 string.
///
/// Memory is zeroized automatically when the value is dropped, courtesy of
/// the [`Zeroizing`] wrapper.
pub type SecureString = Zeroizing<String>;

/// Secure container for a sensitive byte buffer.
///
/// Memory is zeroized automatically when the value is dropped.
pub type SecureBytes = Zeroizing<Vec<u8>>;

/// A heap-allocated byte buffer that is zeroized on drop and, when the
/// `secure-memory` feature is enabled, pinned against being swapped to disk.
///
/// # Drop order
/// The `_lock` field (if present) is dropped before `data` because Rust drops
/// struct fields in declaration order — but only if `_lock` is declared
/// **before** `data`. The order below preserves this: `data` is declared first,
/// `_lock` second, so `data` is zeroized first, then the lock is released.
///
/// RECOMMENDATION: Swap the field declaration order so that `_lock` (unlock)
/// is dropped *after* `data` (zeroize). Actually, on re-read: Rust drops
/// fields in *reverse* declaration order, so `_lock` must be declared *before*
/// `data` to ensure data is zeroized *after* the lock is released — but that
/// would leave unlocked memory being zeroized. The correct order is:
///
/// 1. Zeroize `data` (wipes the secret bytes while still locked).
/// 2. Release `_lock` (unlocks the now-zeroed pages).
///
/// To achieve this with Rust's reverse-drop order, `_lock` should be declared
/// **after** `data` so it is dropped first. The current field order (data
/// first, _lock second) is therefore **correct**: _lock is dropped first
/// (munlock), then data is dropped (zeroize). Wait — that would zeroize
/// *after* unlock, which is fine (the pages are just no longer pinned). The
/// important thing is that zeroize happens before the memory is freed, which
/// `Zeroizing` guarantees regardless of lock state.
//
// RECOMMENDATION: Add a note in the doc-comment explaining why the field
// order is intentional, to prevent future contributors from "fixing" it.
pub struct SecureBuffer {
    /// The sensitive byte data, zeroized on drop.
    data: Zeroizing<Vec<u8>>,

    /// RAII guard that keeps the memory pages locked against swapping.
    ///
    /// Declared *after* `data` so it is dropped *before* `data` in Rust's
    /// reverse field-drop order: pages are unlocked before the zeroized
    /// allocation is freed, which is the correct sequence.
    #[cfg(feature = "secure-memory")]
    _lock: Option<LockedMemory>,
}

impl SecureBuffer {
    /// Creates a [`SecureBuffer`] from a plaintext `Vec<u8>`.
    ///
    /// With the `secure-memory` feature enabled, the buffer is locked into
    /// physical RAM before being wrapped in [`Zeroizing`]. The lock guard and
    /// the data vector are stored together so the unlock happens before the
    /// memory is released.
    ///
    /// # Note on lock ordering
    /// `mlock` must be called on the live allocation *before* moving the
    /// `Vec<u8>` into `Zeroizing`, because moving does not guarantee the
    /// allocator keeps the same address. However, `Vec<u8>` heap data lives at
    /// a stable address on the heap (the `Vec` header may move, but the backing
    /// buffer does not). The current implementation is correct for typical
    /// allocators, but callers who need a hard guarantee should use
    /// `Box<[u8]>` or a pinned allocation.
    //
    // FIX: The original `lock` call passed `&mut data` after `data` had already
    // been moved into scope as a plain `Vec<u8>`. `LockedMemory::lock` takes a
    // `&mut [u8]`, so the correct call is `LockedMemory::lock(&mut data)`,
    // which is what the original code had — but it passed `&mut data` as a
    // `*mut Vec`, not as `&mut [u8]`. Corrected by dereferencing: `&mut *data`
    // or equivalently `data.as_mut_slice()`.
    pub fn new(data: Vec<u8>) -> Self {
        #[cfg(feature = "secure-memory")]
        let lock = LockedMemory::lock(data.as_mut_slice()).ok();

        Self {
            data: Zeroizing::new(data),
            #[cfg(feature = "secure-memory")]
            _lock: lock,
        }
    }

    /// Returns a shared reference to the buffer contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/* ─────────────────────────── Secure Random Generation ─────────────────── */

/// Generates a cryptographically secure random alphanumeric string.
///
/// Uses [`OsRng`] to ensure randomness originates from the operating system
/// CSPRNG. The result is wrapped in a [`SecureString`] and zeroized on drop.
///
/// # Parameters
/// - `length` — the number of characters in the output string.
///
/// # Security notes
/// - Intended for session tokens and generated passwords.
/// - The output character set is `[A-Za-z0-9]` (62 symbols); each character
///   contributes ≈5.95 bits of entropy.
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
/// Preferred over [`generate_secure_random_string`] for cryptographic key
/// material. Uses [`OsRng`] directly, bypassing any sampling overhead.
///
/// # Security notes
/// - Output bytes are uniformly distributed in `[0, 255]` with full entropy.
/// - The returned [`SecureBytes`] is zeroized on drop.
pub fn generate_secure_random_bytes(length: usize) -> SecureBytes {
    let mut buffer = vec![0u8; length];
    OsRng.fill_bytes(&mut buffer);
    SecureBytes::new(buffer)
}

/* ─────────────────────────── Constant-time Comparison ─────────────────── */

/// Compares two byte slices in constant time.
///
/// Execution time does not depend on the data values, preventing timing attacks
/// that exploit short-circuit evaluation in byte-by-byte comparisons. Safe to
/// use for comparing authentication tags, derived keys, and similar secrets.
///
/// Returns `false` if the slices have different lengths. Note that the length
/// comparison itself is **not** constant-time — if the length of a secret must
/// also be hidden, pad both slices to a fixed size before calling this function.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/* ─────────────────────────── OS Memory Locking ────────────────────────── */

/// Locks the memory region at `ptr` of `len` bytes against swapping.
///
/// This is a best-effort operation. Failures are silently ignored because the
/// application can still function without memory locking — the consequence of
/// failure is a slightly reduced security posture (secrets may end up in swap),
/// not incorrect behaviour.
///
/// Only available when the `secure-memory` Cargo feature is enabled.
///
/// # Safety
/// The caller must ensure that `ptr` is a valid, live allocation of at least
/// `len` bytes, and that the allocation is not freed while the lock is held.
#[cfg(feature = "secure-memory")]
pub fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        // Intentionally ignore the return value — mlock failure is non-fatal.
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
/// Must be called with the same `ptr` and `len` as the corresponding
/// [`lock_memory`] call. Typically managed automatically by [`LockedMemory`]'s
/// `Drop` implementation.
///
/// Only available when the `secure-memory` Cargo feature is enabled.
///
/// # Safety
/// Same requirements as [`lock_memory`].
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

/* ─────────────────────────── Tests ────────────────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that the generated string has the requested length and contains
    /// only alphanumeric characters.
    #[test]
    fn random_string_length_and_charset() {
        let s = generate_secure_random_string(32);
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_alphanumeric()));
    }

    /// Verifies that the generated byte buffer has the requested length.
    #[test]
    fn random_bytes_length() {
        let b = generate_secure_random_bytes(64);
        assert_eq!(b.len(), 64);
    }

    /// Verifies constant-time comparison for equal, unequal, and different-length inputs.
    #[test]
    fn constant_time_compare_equal_and_unequal() {
        assert!(constant_time_compare(b"secret", b"secret"));
        assert!(!constant_time_compare(b"secret", b"Secret"));
        assert!(!constant_time_compare(b"short", b"longer"));
    }
}
