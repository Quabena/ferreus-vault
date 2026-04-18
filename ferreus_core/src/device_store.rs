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

use anyhow::Ok;
use std::fs;
use std::path::PathBuf;

use crate::device_key::DeviceKey;

pub struct DeviceKeyStore {
    path: PathBuf,
}

impl DeviceKeyStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load_or_create(&self) -> std::io::Result<DeviceKey> {
        if self.path.exists() {
            let bytes = fs::read(&self.path)?;

            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes..32);

            Ok(DeviceKey { key })
        } else {
            let key = DeviceKey::generate();

            fs::write(&self.path, &key.key)?;

            Ok(key)
        }
    }
}
