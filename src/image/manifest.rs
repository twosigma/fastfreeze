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

use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use crate::{
    consts::*,
    store::{Store, FileExt},
};
use super::{Compression, Encryption};
use std::fmt;

// The image manifest is what describes how to consume an image.
// It holds version, shard location, and compression used.

pub enum ManifestFetchResult {
    Some(ImageManifest),
    VersionMismatch { fetched: String, desired: String },
    NotFound,
}

#[derive(Serialize, Deserialize)]
pub struct ImageManifest {
    pub version: String,
    pub num_shards: u32,
    pub encryption: Option<Encryption>,
    pub compression: Option<Compression>,
    pub shard_prefix: String,
}

impl ImageManifest {
    /// Make a new image manifest. The shard_prefix is INVOCATION_ID which is picked at random.
    /// This can make it easier to tie metrics and log files to a specific checkpoint command.
    pub fn new(num_shards: u32, encrypt: bool, compression: Option<Compression>) -> Self {
        Self {
            version: String::from(CURRENT_IMG_VERSION),
            shard_prefix: INVOCATION_ID.clone(),
            encryption: if encrypt { Some(Encryption::default()) } else { None },
            compression,
            num_shards,
        }
    }

    pub fn to_json(&self) -> String {
        // unwrap() is safe. The JSON serialization can't fail.
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(manifest_json: &str, allow_bad_image_version: bool) -> Result<ManifestFetchResult> {
        use ManifestFetchResult::*;

        // We first parse the JSON uninterpreted to check for the version.
        // If we have a match, we proceed to destructuring the JSON into our ImageDescriptor.
        let manifest: serde_json::Value = serde_json::from_str(manifest_json)
            .with_context(|| format!("Malformed json: {}", manifest_json))?;

        Ok(if manifest["version"] == CURRENT_IMG_VERSION || allow_bad_image_version {
            let manifest = serde_json::from_value(manifest)
                .with_context(|| format!("Failed to parse image descriptor: {}", manifest_json))?;
            Some(manifest)
        } else {
            VersionMismatch {
                fetched: manifest["version"].to_string(),
                desired: CURRENT_IMG_VERSION.to_string(),
            }
        })
    }

    pub fn persist_to_store(&self, store: &dyn Store) -> Result<()> {
        store.file(MANIFEST_FILE_NAME).write("upload manifest", self.to_json().as_bytes())
    }

    pub fn fetch_from_store(store: &dyn Store, allow_bad_image_version: bool) -> Result<ManifestFetchResult> {
        Ok(match store.file(MANIFEST_FILE_NAME).try_read("download manifest")? {
            Some(manifest_json) => Self::from_json(&String::from_utf8_lossy(&manifest_json), allow_bad_image_version)?,
            None => ManifestFetchResult::NotFound,
        })
    }
}

impl fmt::Display for ImageManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version={}, num_shards={} compression={} encryption={} prefix={}",
            self.version, self.num_shards,
            self.compression.as_ref().map_or_else(|| "none".to_string(), |d| format!("{}", d)),
            self.encryption.as_ref().map_or_else(|| "none".to_string(), |d| format!("{}", d)),
            self.shard_prefix)
    }
}
