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
//! When the feature is disabled, [`LockedMemory`] is a zero-sized no-op stub.

use std::io;

/* ------------------- Feature-enabled implementation ---------------------- */

#[cfg(feature = "secure-memory")]
pub struct LockedMemory {
    ptr: *mut u8,
    len: usize,
}

/// # Safety
/// `LockedMemory` holds a raw pointer only so that the `Drop` impl can call
/// `munlock`/`VirtualUnlock` with the original address. The pointee is always
/// a slice owned by the caller (typically a `Vec<u8>` inside `SecureBuffer`),
/// and the caller guarantees that `LockedMemory` is dropped before the slice
/// is freed. No aliasing occurs after construction.
#[cfg(feature = "secure-memory")]
unsafe impl Send for LockedMemory {}

/// See the `Send` impl for the safety rationale.
#[cfg(feature = "secure-memory")]
unsafe impl Sync for LockedMemory {}

#[cfg(feature = "secure-memory")]
impl LockedMemory {
    /// Attempts to lock the memory occupied by `buf` against being swapped.
    ///
    /// Returns `Ok(Self)` on success, or an OS error if `mlock`/`VirtualLock`
    /// fails (e.g. due to resource limits).
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

/* ------------------- No-op stub (feature disabled) ----------------------- */

#[cfg(not(feature = "secure-memory"))]
pub struct LockedMemory;

#[cfg(not(feature = "secure-memory"))]
impl LockedMemory {
    /// No-op stub — memory locking is not available without the
    /// `secure-memory` Cargo feature.
    pub fn lock(_buf: &mut [u8]) -> Result<Self, io::Error> {
        Ok(Self)
    }
}
