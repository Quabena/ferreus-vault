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

//! RAII wrapper for OS-level memory locking (`mlock` / `VirtualLock`).
//!
//! When the `secure-memory` Cargo feature is enabled, [`LockedMemory`] pins a
//! memory region into physical RAM and automatically unlocks it when dropped.
//! When the feature is disabled, [`LockedMemory`] is a zero-sized no-op stub
//! that compiles away entirely.
//!
//! # Usage
//! [`LockedMemory`] is not intended to be used directly by application code.
//! It is constructed by [`crate::memory::SecureBuffer`] and stored alongside
//! the data it protects so that the lock is released exactly when the data is
//! freed.
//!
//! # Platform notes
//! - **Linux / Unix**: `mlock(2)` / `munlock(2)` via `libc`.
//! - **Windows**: `VirtualLock` / `VirtualUnlock` via `windows-sys`.
//! - **Other targets**: no-op stub; memory locking is silently unavailable.
//!
//! # Security note
//! Memory locking prevents the OS from swapping sensitive pages to disk, but
//! it does **not** prevent other processes from reading the memory via
//! `/proc/<pid>/mem` (Linux) or equivalent. Combine with process isolation and
//! minimal privilege for meaningful protection.

use std::io;

/* ─────────────────────────── Feature-enabled implementation ───────────── */

/// RAII guard that keeps a memory region locked in physical RAM.
///
/// Constructed via [`LockedMemory::lock`]; the lock is released when this
/// value is dropped.
///
/// Only fully implemented when the `secure-memory` Cargo feature is enabled.
/// Without the feature, this is a zero-sized no-op stub.
#[cfg(feature = "secure-memory")]
pub struct LockedMemory {
    /// Pointer to the first byte of the locked region.
    ptr: *mut u8,
    /// Number of bytes in the locked region.
    len: usize,
}

/// # Safety
/// [`LockedMemory`] holds a raw pointer only so that `Drop` can call
/// `munlock` / `VirtualUnlock` with the original address. The pointee is
/// always a slice owned by the caller (typically the `Vec<u8>` backing a
/// `SecureBuffer`). The caller guarantees that:
///
/// 1. [`LockedMemory`] is dropped before the owning slice is freed.
/// 2. No other `LockedMemory` guard is created for the same region
///    concurrently (double-lock is harmless on most OSes but wasteful).
///
/// These invariants are enforced structurally by [`crate::memory::SecureBuffer`],
/// which stores the guard alongside the data and drops them together.
#[cfg(feature = "secure-memory")]
unsafe impl Send for LockedMemory {}

/// See the `Send` implementation for the full safety rationale.
#[cfg(feature = "secure-memory")]
unsafe impl Sync for LockedMemory {}

#[cfg(feature = "secure-memory")]
impl LockedMemory {
    /// Attempts to lock the memory occupied by `buf` against being swapped.
    ///
    /// Returns `Ok(Self)` on success, or an [`io::Error`] if `mlock` /
    /// `VirtualLock` fails (e.g., due to process resource limits — see
    /// `RLIMIT_MEMLOCK` on Linux).
    ///
    /// # Errors
    /// - On Unix: the OS error returned by `mlock(2)`.
    /// - On Windows: the OS error returned by `VirtualLock`.
    pub fn lock(buf: &mut [u8]) -> Result<Self, io::Error> {
        let ptr = buf.as_mut_ptr();
        let len = buf.len();

        #[cfg(unix)]
        unsafe {
            if libc::mlock(ptr as *const libc::c_void, len) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualLock;
            if VirtualLock(ptr as *mut _, len) == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self { ptr, len })
    }
}

#[cfg(feature = "secure-memory")]
impl Drop for LockedMemory {
    /// Releases the memory lock when the guard is dropped.
    ///
    /// Any OS errors from `munlock` / `VirtualUnlock` are silently ignored —
    /// there is no meaningful recovery action available in a destructor.
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.ptr as *const libc::c_void, self.len);
        }

        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Memory::VirtualUnlock;
            VirtualUnlock(self.ptr as *mut _, self.len);
        }
    }
}

/* ─────────────────────────── No-op stub (feature disabled) ────────────── */

/// Zero-sized no-op stub used when the `secure-memory` feature is disabled.
///
/// This type compiles to nothing at runtime. It exists so that code that
/// optionally holds a `LockedMemory` does not need `#[cfg]` guards at every
/// use site.
#[cfg(not(feature = "secure-memory"))]
pub struct LockedMemory;

#[cfg(not(feature = "secure-memory"))]
impl LockedMemory {
    /// No-op stub — memory locking is unavailable without the `secure-memory`
    /// Cargo feature.
    ///
    /// Always succeeds (returns `Ok(Self)`). The `buf` argument is accepted
    /// but not used, so call sites compile without `#[cfg]` guards.
    #[allow(unused_variables)]
    pub fn lock(_buf: &mut [u8]) -> Result<Self, io::Error> {
        Ok(Self)
    }
}
