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
    collections::HashSet,
    path::{Path, PathBuf},
    time::{SystemTime, Duration},
};
use nix::{
    poll::{PollFd, PollFlags},
    sys::signal::{self, killpg},
    unistd::Pid,
};
use structopt::StructOpt;
use serde::Serialize;
use crate::{
    consts::*,
    store,
    image::{ImageManifest, Compressor, shard, CpuBudget},
    process::{Command, ProcessExt, ProcessGroup, Stdio},
    metrics::{with_metrics, emit_metrics},
    util::poll_nointr,
    image_streamer::{Stats, ImageStreamer},
    lock::with_checkpoint_restore_lock,
    criu,
    filesystem,
    virt,
};
use super::run::AppConfig;


/// Perform a checkpoint of the running application
#[derive(StructOpt, PartialEq, Debug, Serialize)]
#[structopt(after_help("\
ENVS:
    FF_METRICS_RECORDER         When specified, FastFreeze invokes the specified program to report metrics.
                                The metrics are formatted in JSON and passed as first argument
    CRIU_OPTS                   Additional arguments to pass to CRIU, whitespace separated
    S3_CMD                      Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD                      Command to access Google Storage. Defaults to 'gsutil'
    TAR_CMD                     Command to tar the file system. Defaults to 'tar'"
))]
pub struct Checkpoint {
    /// Image URL, defaults to the value used during the run command
    #[structopt(long)]
    image_url: Option<String>,

    /// Dir/file to include in the image in addition to the ones specified during the run command.
    /// May be specified multiple times. Multiple paths can also be specified colon separated.
    // require_delimiter is set to avoid clap's non-standard way of accepting lists.
    #[structopt(long="preserve-path", name="path", require_delimiter=true, value_delimiter=":")]
    preserved_paths: Vec<PathBuf>,

    /// Leave application running after checkpoint
    #[structopt(long)]
    leave_running: bool,

    /// Level of parallelism. Split the image in multiple shards.
    // We use a default of 4 shards to benefit from some parallelism.
    // It should be set to something related to the number of CPUs available.
    #[structopt(long, default_value="4")]
    num_shards: u32,

    /// Amount of CPU at disposal. Possible values are [low, medium, high].
    /// Currently, `low` skips compression, `medium` uses lz4, and
    /// high uses zstd.
    #[structopt(long, default_value="medium")]
    cpu_budget: CpuBudget,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}

fn is_app_running() -> bool {
    Path::new("/proc").join(APP_ROOT_PID.to_string()).exists()
}

pub fn do_checkpoint(opts: Checkpoint) -> Result<Stats> {
    let Checkpoint {
        image_url, num_shards, cpu_budget,
        preserved_paths, leave_running, verbose: _,
    } = opts;

    // We override TMPDIR with a safe location. The uploader (or metrics CLI)
    // may create a tmp file (e.g., bash script using here documents). This
    // would cause tar to fail as it detects changes in /tmp.
    // `NO_PRESERVE_FF_DIR` is excluded from the list of paths to preserve.
    std::env::set_var("TMPDIR", &*NO_PRESERVE_FF_DIR);

    let mut preserved_paths: HashSet<_> = preserved_paths.into_iter().collect();

    let config = AppConfig::restore()?;

    // If the image_url is not supplied, we use the one that we stashed during
    // the run operation.
    let image_url = image_url.unwrap_or(config.image_url);

    // We emit a "checkpoint_start" event to make it easier to track down
    // containers that vanish during checkpoints. We don't wait for the metrics
    // process to complete, it would delay checkpointing.
    let _metrics_p_reaper = {
        let event = json!({"action": "checkpoint_start", "image_url": image_url});
        emit_metrics(event)?.map(|p| p.reap_on_drop())
    };

    // As for preserved_paths, we join all the paths we know of.
    // There is the downside of not being able to forget a path that was once preserved.
    // The upside is that is less prone to bugs for users.
    preserved_paths.extend(config.preserved_paths);

    ensure!(is_app_running(), "Application is not running");

    // The manifest contains the name of the shards, which are generated at random.
    // We combine it with the store to generate the shard upload commands.
    // A shard upload command is of the form:
    //     "lz4 -1 - - | aws s3 cp - s3://bucket/img/XXXXXX.ffs"
    let img_manifest = ImageManifest::new(num_shards, Compressor::from(cpu_budget));
    let store = store::from_url(&image_url)?;
    let shard_upload_cmds = shard::upload_cmds(&img_manifest, &*store);

    info!("Checkpointing application to {} (num_shards={} compressor={:?} prefix={})",
          image_url, num_shards, img_manifest.compressor, img_manifest.shard_prefix);

    // `pgrp` monitors all our child processes. If one fails, the whole group fails
    let mut pgrp = ProcessGroup::new()?;
    let mut img_streamer = ImageStreamer::spawn_capture(num_shards as usize)?;
    img_streamer.process.join(&mut pgrp);

    // Spawn the upload processes connected to the image streamer's output
    for (upload_cmd, shard_pipe) in shard_upload_cmds.into_iter().zip(img_streamer.shard_pipes) {
        Command::new_shell(&upload_cmd)
            .stdin(Stdio::from(shard_pipe))
            .enable_stderr_logging("upload")
            .spawn()?
            .join(&mut pgrp);
    }

    // Wait for the imager socket to be ready.
    img_streamer.progress.wait_for_socket_init()?;

    // Spawn the CRIU dump process. CRIU sends the image to the image streamer.
    // CRIU will leave the application in a stopped state when done,
    // so that we can continue tarring the filesystem.
    // Note: it would be tempting to SIGCONT the application upon failures, but
    // we should not. It's CRIU's responsability to do so. If it didn't SIGCONT
    // the app, then something bad has happened, and it would be unsafe to let
    // the application run in a bad state.
    criu::criu_dump_cmd()
        .enable_stderr_logging("criu")
        .spawn()?
        .join_as_non_killable(&mut pgrp);

    // We want to start dumping the file system ASAP, but we must wait for the
    // application to be stopped by CRIU, otherwise the filesystem might still
    // be changing under us. We wait for the "checkpoint-start" message from the
    // streamer progress pipe.
    // We must also check for the CRIU process, otherwise, we could hang forever
    while pgrp.try_wait_for_success()? {
        let mut poll_fds = pgrp.poll_fds();
        poll_fds.push(PollFd::new(img_streamer.progress.fd, PollFlags::POLLIN));
        let timeout = -1;
        poll_nointr(&mut poll_fds, timeout)?;

        // Check if we have something to read on the progress pipe.
        // unwrap() is safe. We had pushed a value in the vector.
        let streamer_poll_fd = poll_fds.last().expect("missing streamer poll_fd");
        // unwrap() is safe: we assume the kernel returns valid bits in `revents`.
        if !streamer_poll_fd.revents().expect("revents invalid").is_empty() {
            img_streamer.progress.wait_for_checkpoint_start()?;
            break;
        }
    }
    debug!("Checkpoint started, application is frozen");

    {
        // We save the current time of the application so we can resume time
        // where we left off. The time config file goes on the file system.
        // We also save the image_url and preserved paths.
        let app_clock = virt::time::ConfigPath::default().read_current_app_clock()?;
        ensure!(app_clock >= 0, "Computed app clock is negative: {}ns", app_clock);
        debug!("App clock: {:.1}s", Duration::from_nanos(app_clock as u64).as_secs_f64());

        let config = AppConfig {
            image_url: image_url.to_string(),
            preserved_paths: preserved_paths.clone(),
            app_clock,
            // Ideally, we want the clock time once the checkpoint has ended,
            // but that would be a bit difficult. We could though.
            // It would involve adding the config.json as an external file
            // into to the streamer (like fs.tar), and stream it at the very end.
            // For now, we have the time at which the checkpoint started.
            created_at: SystemTime::now(),
        };
        config.save()?;
    }

    // We dump the filesystem with tar. The stdout of tar connects to
    // criu-image-streamer, which incorporates the tarball into the checkpoint
    // image.
    debug!("Dumping filesystem");
    filesystem::tar_cmd(preserved_paths, img_streamer.tar_fs_pipe.unwrap())
        .enable_stderr_logging("tar")
        .spawn()?
        .wait_for_success()?;
    debug!("Filesystem dumped. Finishing dumping processes");

    // Wait for checkpoint to complete
    pgrp.wait_for_success()?;

    let stats = img_streamer.progress.wait_for_stats()?;
    stats.show();

    if leave_running {
        trace!("Resuming application");
        killpg(Pid::from_raw(APP_ROOT_PID), signal::SIGCONT)
            .context("Failed to resume application")?;
    } else {
        // We kill the app later, once metrics are emitted.
    }

    // At this point, all the shards are written successfully. We can now write
    // the manifest file to the store. The manifest file existence indicates
    // whether the image exists, so it must be written at the very end.
    debug!("Writing image manifest");
    img_manifest.persist_to_store(&*store)
        .with_context(|| format!("Failed to upload image manifest at {}", image_url))?;

    info!("Checkpoint to {} complete. Took {:.1}s",
          image_url, START_TIME.elapsed().as_secs_f64());

    Ok(stats)
}

impl super::CLI for Checkpoint {
    fn run(self) -> Result<()> {
        // Holding the lock while invoking the metrics CLI is preferable to avoid
        // disturbing another instance trying to do PID control.
        with_checkpoint_restore_lock(|| {
            let leave_running = self.leave_running;
            with_metrics("checkpoint",
                || do_checkpoint(self),
                |stats| json!({"stats": stats}))?;

            // We kill the app after the metrics are emitted. Killing the app
            // risk terminating the container, preventing metrics from being emitted.
            if !leave_running {
                debug!("Killing application");
                killpg(Pid::from_raw(APP_ROOT_PID), signal::SIGKILL)
                    .context("Failed to kill application")?;
            }

            Ok(())
        })
    }
}
