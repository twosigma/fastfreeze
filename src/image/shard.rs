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
use std::path::PathBuf;
use super::ImageManifest;
use crate::store::Store;

fn shard_filename(shard_prefix: &str, shard_index: u32) -> String {
    // .ffs stands for fastfreeze shard
    format!("{}-{}.ffs", shard_prefix, shard_index+1)
}

pub fn upload_cmds(
    img_manifest: &ImageManifest,
    passphrase_file: Option<&PathBuf>,
    store: &dyn Store,
) -> Result<Vec<String>> {
    let cmd_common = {
        let mut cmd = Vec::new();

        if let Some(ref compression) = img_manifest.compression {
            cmd.push(compression.compress_cmd().to_string());
        }

        if let Some(ref encryption) = img_manifest.encryption {
            let passphrase_file = passphrase_file.ok_or_else(|| anyhow!(
                "The image must be encrypted. Use --passphrase-file to provide an encryption passphrase"))?;
            cmd.push(encryption.encrypt_cmd(passphrase_file.as_path()));
        }
        cmd
    };

    Ok((0..img_manifest.num_shards).map(|shard_index| {
        let file = store.file(&shard_filename(&img_manifest.shard_prefix, shard_index));
        let mut cmd = cmd_common.clone();
        cmd.push(file.upload_shell_cmd());
        cmd.join(" | ")
    }).collect())
}

pub fn download_cmds(
    img_manifest: &ImageManifest,
    passphrase_file: Option<&PathBuf>,
    store: &dyn Store
) -> Result<Vec<String>> {
    let cmd_common = {
        let mut cmd = Vec::new();

        if let Some(ref encryption) = img_manifest.encryption {
            let passphrase_file = passphrase_file.ok_or_else(|| anyhow!(
                "The image is encrypted. Use --passphrase-file to provide an encryption passphrase"))?;
            cmd.push(encryption.decrypt_cmd(passphrase_file.as_path()));
            info!("Decrypting image with passphrase from file {}", passphrase_file.display());
        }

        if let Some(ref compression) = img_manifest.compression {
            cmd.push(compression.decompress_cmd().to_string());
        }
        cmd
    };

    Ok((0..img_manifest.num_shards).map(|shard_index| {
        let file = store.file(&shard_filename(&img_manifest.shard_prefix, shard_index));
        let mut cmd: Vec<String> = vec![file.download_shell_cmd()];
        cmd.append(&mut cmd_common.clone());
        cmd.join(" | ")
    }).collect())
}
