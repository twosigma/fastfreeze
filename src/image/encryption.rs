//  Copyright 2020 Two Sigma Investments, LP.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use anyhow::Result;
use std::{
    path::Path,
    fmt,
};
use serde::{Serialize, Deserialize};
use crate::consts::*;

#[derive(Serialize, Deserialize)]
pub struct Encryption {
    pub cipher: String,
}

impl Encryption {
    pub fn new(cipher: String) -> Self {
        Self { cipher }
    }

    pub fn encrypt_cmd(&self, passphrase_file: &Path) -> String {
        format!("openssl enc -e -{} -pbkdf2 -pass file:{}",
            self.cipher, passphrase_file.display())
    }

    pub fn decrypt_cmd(&self, passphrase_file: &Path) -> String {
        format!("openssl enc -d -{} -pbkdf2 -pass file:{}",
            self.cipher, passphrase_file.display())
    }
}

impl Default for Encryption {
    fn default() -> Self {
        Self::new(DEFAULT_ENCRYPTION_CIPHER.to_string())
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cipher)
    }
}

pub fn check_passphrase_file_exists(passphrase_file: &Path) -> Result<()> {
    ensure!(passphrase_file.exists(),
        "The passphrase file {} is not accessible", passphrase_file.display());
    Ok(())
}
