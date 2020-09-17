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
use std::{
    os::unix::io::{RawFd, AsRawFd},
    fs, io::BufReader,
    io::BufRead,
    io::Lines, path::Path,
};
use serde::{Serialize, Deserialize};
use crate::{
    consts::*,
    util::Pipe,
    process::{Command, Process, PipeCommandExt},
};


pub struct Progress {
    pub fd: RawFd,
    pub lines: Lines<BufReader<fs::File>>,
}

impl Progress {
    fn get_next_progress_line(&mut self) -> Result<String> {
        Ok(self.lines.next()
            .ok_or_else(|| anyhow!("EOF unexpectedly reached"))
            .context("Failed to read progress from the streamer")??)
    }

    pub fn wait_for_socket_init(&mut self) -> Result<()> {
        ensure!(self.get_next_progress_line()? == "socket-init",
                "criu-image-streamer failed to initialize");
        Ok(())
    }

    pub fn wait_for_checkpoint_start(&mut self) -> Result<()> {
        ensure!(self.get_next_progress_line()? == "checkpoint-start",
                "criu-image-streamer failed to send start message");
        Ok(())
    }

    pub fn wait_for_stats(&mut self) -> Result<Stats> {
        let stats_json = self.get_next_progress_line()?;
        Ok(serde_json::from_str::<ImageStreamerStats>(&stats_json)?.into())
    }
}

pub struct ImageStreamer {
    pub process: Process,
    pub progress: Progress,
    pub tar_fs_pipe: Option<fs::File>,
    pub shard_pipes: Vec<fs::File>,
}

impl ImageStreamer {
    pub fn spawn_capture(num_shards: usize) -> Result<Self> {
        let progress = Pipe::new_output()?;
        let fs_tar = Pipe::new_input()?;

        let shards = (0..num_shards)
            .map(|_| Pipe::new_output())
            .collect::<Result<Vec<_>>>()?;

        let mut cmd = Command::new(&[
            "criu-image-streamer",
            "--progress-fd", &progress.write.as_raw_fd().to_string(),
            "--ext-file-fds", &format!("fs.tar:{}", fs_tar.read.as_raw_fd()),
            "--shard-fds", &shards.iter()
                .map(|o| o.write.as_raw_fd().to_string())
                .collect::<Vec<_>>().join(","),
        ]);
        cmd
            .arg("--images-dir").arg(&*CRIU_SOCKET_DIR)
            .arg("capture")
            .enable_stderr_logging("streamer");

        Ok(Self {
            process: cmd.spawn()?,
            progress: Progress {
                fd: progress.read.as_raw_fd(),
                lines: BufReader::new(progress.read).lines(),
            },
            tar_fs_pipe: Some(fs_tar.write),
            shard_pipes: shards.into_iter().map(|o| o.read).collect(),
        })
    }

    pub fn spawn_serve(num_shards: usize) -> Result<Self> {
        let progress = Pipe::new_output()?;
        let fs_tar = Pipe::new_output()?;

        let shards = (0..num_shards)
            .map(|_| Pipe::new_input())
            .collect::<Result<Vec<_>>>()?;

        let mut cmd = Command::new(&[
            "criu-image-streamer",
            "--progress-fd", &progress.write.as_raw_fd().to_string(),
            "--ext-file-fds", &format!("fs.tar:{}", fs_tar.write.as_raw_fd()),
            "--shard-fds", &shards.iter()
                .map(|o| o.read.as_raw_fd().to_string())
                .collect::<Vec<_>>().join(","),
        ]);
        cmd
            .arg("--images-dir").arg(&*CRIU_SOCKET_DIR)
            .arg("serve")
            .enable_stderr_logging("streamer");

        Ok(Self {
            process: cmd.spawn()?,
            progress: Progress {
                fd: progress.read.as_raw_fd(),
                lines: BufReader::new(progress.read).lines(),
            },
            tar_fs_pipe: Some(fs_tar.read),
            shard_pipes: shards.into_iter().map(|o| o.write).collect(),
        })
    }

    pub fn spawn_extract(num_shards: usize, output_dir: &Path) -> Result<Self> {
        let progress = Pipe::new_output()?;

        let shards = (0..num_shards)
            .map(|_| Pipe::new_input())
            .collect::<Result<Vec<_>>>()?;

        let mut cmd = Command::new(&[
            "criu-image-streamer",
            "--progress-fd", &progress.write.as_raw_fd().to_string(),
            "--shard-fds", &shards.iter()
                .map(|o| o.read.as_raw_fd().to_string())
                .collect::<Vec<_>>().join(","),
            "--images-dir"
         ]);
         cmd.arg(output_dir)
            .arg("extract")
            .enable_stderr_logging("streamer");

        Ok(Self {
            process: cmd.spawn()?,
            progress: Progress {
                fd: progress.read.as_raw_fd(),
                lines: BufReader::new(progress.read).lines(),
            },
            tar_fs_pipe: None,
            shard_pipes: shards.into_iter().map(|o| o.write).collect(),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct ImageStreamerStats {
    pub shards: Vec<ImageStreamerShardStat>,
}
#[derive(Serialize, Deserialize)]
pub struct ImageStreamerShardStat {
    pub size: u64,
    pub transfer_duration_millis: u128,
}

// These are emitted for metrics
#[derive(Serialize, Deserialize)]
pub struct Stats {
    pub total_size_mb: f64,
    pub total_duration_sec: f64,
    pub rate_mb_per_sec: f64,
    pub shards: Vec<ShardStat>,
}
#[derive(Serialize, Deserialize)]
pub struct ShardStat {
    pub size_mb: f64,
    pub duration_sec: f64,
    pub rate_mb_per_sec: f64,
}

impl Stats {
    pub fn show(&self) {
        info!("Uncompressed image size is {:.0} MiB, rate: {:.0} MiB/s",
              self.total_size_mb, self.rate_mb_per_sec);

        if log_enabled!(log::Level::Debug) && self.shards.len() > 1 {
            for (i, shard) in self.shards.iter().enumerate() {
                debug!("  Shard {}: {:.0} MiB, rate: {:.0} MiB/s",
                       i+1, shard.size_mb, shard.rate_mb_per_sec);
            }
        }

        // To show the compressed rates, we need to examine the output pipes.
        // But that will cost us some CPU overhead as there's no way to get
        // stats on a kernel pipe, to my knowledge.
    }
}

impl From<ImageStreamerStats> for Stats {
    fn from(stats: ImageStreamerStats) -> Self {
        let total_size: u64 = stats.shards.iter().map(|s| s.size).sum();
        let total_duration_millis = stats.shards.iter().map(|s| s.transfer_duration_millis).max().unwrap_or(0);

        let total_size_mb = total_size as f64 / MB as f64;
        let total_duration_sec = total_duration_millis as f64 / 1000.0;
        let rate_mb_per_sec = if total_duration_sec == 0.0 { 0.0 } else { total_size_mb / total_duration_sec };

        let shards = stats.shards.into_iter().map(|s| {
            let size_mb = s.size as f64 / MB as f64;
            let duration_sec = s.transfer_duration_millis as f64 / 1000.0;
            let rate_mb_per_sec = if duration_sec == 0.0 { 0.0 } else { size_mb / duration_sec };
            ShardStat { size_mb, duration_sec, rate_mb_per_sec }
        }).collect::<Vec<_>>();

        Self { total_size_mb, total_duration_sec, rate_mb_per_sec, shards }
    }
}
