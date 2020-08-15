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

use super::ImageManifest;
use crate::store::Store;

fn shard_filename(shard_prefix: &str, shard_index: u32) -> String {
    // .ffs stands for fastfreeze shard
    format!("{}-{}.ffs", shard_prefix, shard_index+1)
}

pub fn upload_cmds(img_desc: &ImageManifest, store: &dyn Store) -> Vec<String> {
    (0..img_desc.num_shards).map(|shard_index| {
        let file = store.file(&shard_filename(&img_desc.shard_prefix, shard_index));

        match img_desc.compressor.compress_cmd() {
            Some(comp_cmd) => format!("{} | {}", comp_cmd, file.upload_shell_cmd()),
            None => file.upload_shell_cmd(),
        }
    }).collect()
}

pub fn download_cmds(img_desc: &ImageManifest, store: &dyn Store) -> Vec<String> {
    (0..img_desc.num_shards).map(|shard_index| {
        let file = store.file(&shard_filename(&img_desc.shard_prefix, shard_index));

        match img_desc.compressor.decompress_cmd() {
            Some(decomp_cmd) => format!("{} | {}", file.download_shell_cmd(), decomp_cmd),
            None => file.download_shell_cmd(),
        }
    }).collect()
}
