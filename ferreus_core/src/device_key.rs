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

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub const DEVICE_KEY_LEN: usize = 32;

/// Device-specific secret
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DeviceKey {
    pub key: [u8; DEVICE_KEY_LEN],
}

impl DeviceKey {
    pub fn generate() -> Self {
        let mut key = [0u8; DEVICE_KEY_LEN];
        OsRng.fill_bytes(&mut key);

        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}
