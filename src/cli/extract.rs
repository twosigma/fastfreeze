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
use url::Url;
use structopt::StructOpt;
use serde::Serialize;
use crate::{
    consts::*,
    store,
    image::{ManifestFetchResult, ImageManifest, shard, check_passphrase_file_exists},
    process::{Command, ProcessExt, ProcessGroup, Stdio},
    image_streamer::ImageStreamer,
};

/// Extract a FastFreeze image to local disk
#[derive(StructOpt, PartialEq, Debug, Serialize)]
#[structopt(after_help("\
ENVS:
    S3_CMD   Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD   Command to access Google Storage. Defaults to 'gsutil'"
))]
pub struct Extract {
    /// Image URL, which can also be a regular local path
    #[structopt(short, long)]
    image_url: String,

    /// Output directory where to extract the image.
    /// Defaults to the last path component of image-url.
    #[structopt(short, long)]
    output_dir: Option<PathBuf>,

    /// Allow restoring of images that don't match the version we expect.
    #[structopt(long)]
    allow_bad_image_version: bool,

    /// Provide a file containing the passphrase to be used for encrypting
    /// or decrypting the image. For security concerns, using a ramdisk
    /// like /dev/shm to store the passphrase file is preferable.
    #[structopt(long)]
    passphrase_file: Option<PathBuf>,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}

pub fn extract_image(
    shard_download_cmds: Vec<String>,
    output_dir: PathBuf,
) -> Result<()> {
    let num_shards = shard_download_cmds.len();

    info!("Extracting image from {} shards", num_shards);

    let mut pgrp = ProcessGroup::new()?;
    let mut img_streamer = ImageStreamer::spawn_extract(num_shards, &output_dir)?;
    img_streamer.process.join(&mut pgrp);

    for (download_cmd, shard_pipe) in shard_download_cmds.into_iter().zip(img_streamer.shard_pipes) {
        Command::new_shell(&download_cmd)
            .stdout(Stdio::from(shard_pipe))
            .spawn()?
            .join(&mut pgrp);
    }

    pgrp.wait_for_success()?;

    let stats = img_streamer.progress.wait_for_stats()?;
    stats.show();

    info!("Image extracted to {}. Took {:.1}s",
          output_dir.display(), START_TIME.elapsed().as_secs_f64());

    Ok(())
}

impl super::CLI for Extract {
    fn run(self) -> Result<()> {
        let Self { image_url, output_dir,
            allow_bad_image_version, passphrase_file, verbose: _
        } = self;

        let output_dir = match output_dir {
            Some(output_dir) => output_dir,
            None => {
                Url::parse(&image_url)?.path_segments()
                    .and_then(|paths| paths.last())
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow!("Supply an output_dir"))?
            }
        };

        if let Some(ref passphrase_file) = passphrase_file {
            check_passphrase_file_exists(passphrase_file)?;
        }

        let store = store::from_url(&image_url)?;
        store.prepare(false)?;

        info!("Fetching image manifest for {}", image_url);

        match ImageManifest::fetch_from_store(&*store, allow_bad_image_version)? {
            ManifestFetchResult::Some(img_manifest) => {
                debug!("Image manifest found: {}", img_manifest);
                let dl_cmds = shard::download_cmds(
                    &img_manifest, passphrase_file.as_ref(), &*store)?;
                extract_image(dl_cmds, output_dir)?;
            }
            ManifestFetchResult::VersionMismatch { fetched, desired } => {
                bail!("Image manifest found, but has version {} while the expected version is {}. \
                       You may try again with --allow-bad-image-version",
                      fetched, desired);
            }
            ManifestFetchResult::NotFound => {
                bail!("Image manifest not found, running app normally");
            }
        }

        Ok(())
    }
}
