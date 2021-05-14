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
    path::PathBuf,
    time::{SystemTime, Duration},
};
use nix::{
    poll::{PollFd, PollFlags},
    sys::signal,
    unistd::Pid,
};
use structopt::StructOpt;
use serde::Serialize;
use crate::{
    consts::*,
    store::ImageUrl,
    container,
    image::{ImageManifest, CpuBudget, shard, check_passphrase_file_exists},
    process::{Command, ProcessExt, ProcessGroup, Stdio},
    metrics::{with_metrics, emit_metrics},
    util::poll_nointr,
    image_streamer::{Stats, ImageStreamer},
    lock::with_checkpoint_restore_lock,
    signal::{kill_process_tree, get_proc_state},
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
    GS_CMD                      Command to access Google Storage. Defaults to 'gcsthin'
    TAR_CMD                     Command to tar the file system. Defaults to 'tar'"
))]
pub struct Checkpoint {
    /// Image URL, defaults to the value used during the run command
    #[structopt(short, long)]
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
    /// `high` uses zstd.
    #[structopt(long, default_value="medium")]
    cpu_budget: CpuBudget,

    /// Enable image encryption. This points to a file containing a passphrase
    /// used to encrypt the image. The passphrase should contain at least 256 bits
    /// of entropy.
    #[structopt(long)]
    passphrase_file: Option<PathBuf>,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Checkpoint the specified application. See the run command help about
    /// --app-name for more details.
    #[structopt()]
    app_name: Option<String>,
}

pub fn do_checkpoint(opts: Checkpoint) -> Result<Stats> {
    let Checkpoint {
        image_url, num_shards, cpu_budget, passphrase_file,
        preserved_paths, leave_running, app_name: _, verbose: _,
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
    let image_url = ImageUrl::parse(&image_url.unwrap_or(config.image_url))?;

    // As for preserved_paths, we join all the paths we know of.
    // There is the downside of not being able to forget a path that was once preserved.
    // The upside is that is less prone to bugs for users.
    preserved_paths.extend(config.preserved_paths);

    // For the passphrase_file, we take the one provided, or the one specified in
    // a previous operation. This means that once we use encryption, there is no
    // way to go back to using no encryption.
    // Note that if the passphrase file is contained in the preserved_paths,
    // we'll include it. It would be a little odd, but not necessarily harmful.
    // We won't emit a warning if that's the case.
    let passphrase_file = passphrase_file.or(config.passphrase_file);
    if let Some(ref passphrase_file) = passphrase_file {
        check_passphrase_file_exists(passphrase_file)?;
    }

    // The manifest contains the name of the shards, which are generated at random.
    // We combine it with the store to generate the shard upload commands.
    // A shard upload command is of the form:
    //     "lz4 -1 - - | aws s3 cp - s3://bucket/img/XXXXXX.ffs"
    let img_manifest = ImageManifest::new(
        num_shards, passphrase_file.is_some(), cpu_budget.into());

    let store = image_url.store();
    let shard_upload_cmds = shard::upload_cmds(
        &img_manifest, passphrase_file.as_ref(), &*store)?;

    // We emit a "checkpoint_start" event to make it easier to track down
    // containers that vanish during checkpoints. We don't wait for the metrics
    // process to complete, it would delay checkpointing.
    let _metrics_p_reaper = {
        let event = json!({"action": "checkpoint_start", "image_url": image_url.to_string()});
        emit_metrics(event)?.map(|p| p.reap_on_drop())
    };

    info!("Checkpointing application to {} ({})", image_url, img_manifest);
    if let Some(ref passphrase_file) = passphrase_file {
        info!("Encrypting image with passphrase from file {}", passphrase_file.display());
    }

    // `pgrp` monitors all our child processes. If one fails, the whole group fails
    let mut pgrp = ProcessGroup::new()?;
    let mut img_streamer = ImageStreamer::spawn_capture(num_shards as usize)?;
    img_streamer.process.join(&mut pgrp);

    // Spawn the upload processes connected to the image streamer's output
    for (upload_cmd, shard_pipe) in shard_upload_cmds.into_iter().zip(img_streamer.shard_pipes) {
        Command::new_shell(&upload_cmd)
            .stdin(Stdio::from(shard_pipe))
            .enable_stderr_logging("upload shard")
            .spawn()?
            .join(&mut pgrp);
    }

    // Wait for the imager socket to be ready.
    img_streamer.progress.wait_for_socket_init()?;

    // Spawn the CRIU dump process. CRIU sends the image to the image streamer.
    // CRIU will leave the application in a stopped state when done,
    // so that we can continue tarring the filesystem.
    let criu_ps = criu::criu_dump_cmd()
        .enable_stderr_logging("criu")
        .spawn()?
        .join_as_non_killable(&mut pgrp);

    // Fome now on, we want to SIGCONT the application if and if only the CRIU
    // process succeeds. If it failed, it's CRIU's responsability to resume the app.
    // In the case that CRIU didn't resume the app, it would be unsafe to let
    // the application run as it might be in an incorrect state (e.g., having
    // CRIU's parasite still installed).
    // If the CRIU process succeeded (but the upload streams failed), we still
    // want to resume the application.

    // Extract certain fields upfront to avoid compile error due to use of
    // partial values borrowed in the following closure
    let inherited_resources = config.inherited_resources;
    let mut img_streamer_progress = img_streamer.progress;
    let img_streamer_tar_fs_pipe = img_streamer.tar_fs_pipe;

    let stats = || -> Result<Stats> {
        // We want to start dumping the file system ASAP, but we must wait for the
        // application to be stopped by CRIU, otherwise the filesystem might still
        // be changing under us. We wait for the "checkpoint-start" message from the
        // streamer progress pipe.
        // We must also check for the CRIU process, otherwise, we could hang forever
        while pgrp.try_wait_for_success()? {
            let mut poll_fds = pgrp.poll_fds();
            poll_fds.push(PollFd::new(img_streamer_progress.fd, PollFlags::POLLIN));
            let timeout = -1;
            poll_nointr(&mut poll_fds, timeout)?;

            // Check if we have something to read on the progress pipe.
            // unwrap() is safe. We had pushed a value in the vector.
            let streamer_poll_fd = poll_fds.last().expect("missing streamer poll_fd");
            // unwrap() is safe: we assume the kernel returns valid bits in `revents`.
            if !streamer_poll_fd.revents().expect("revents invalid").is_empty() {
                img_streamer_progress.wait_for_checkpoint_start()?;
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
                passphrase_file,
                app_clock,
                // Ideally, we want the clock time once the checkpoint has ended,
                // but that would be a bit difficult. We could though.
                // It would involve adding the config.json as an external file
                // into to the streamer (like fs.tar), and stream it at the very end.
                // For now, we have the time at which the checkpoint started.
                created_at: SystemTime::now(),
                inherited_resources,
            };
            config.save()?;
        }

        // We dump the filesystem with tar. The stdout of tar connects to
        // criu-image-streamer, which incorporates the tarball into the checkpoint
        // image.
        // Note that CRIU can complete at any time, but it leaves the application in
        // a stopped state, so the filesystem remains consistent.
        debug!("Dumping filesystem");
        let tar_ps = filesystem::tar_cmd(preserved_paths, img_streamer_tar_fs_pipe.unwrap())
            .enable_stderr_logging("tar")
            .spawn()?
            .join(&mut pgrp);
        pgrp.get_mut(tar_ps).wait()?; // wait for tar to finish

        pgrp.try_wait_for_success()?; // if tar errored, this is where we exit
        // We print this debug message so that in the logs, we can have a timestamp
        // to tell us how long it took. Maybe it would be better to have a metric event.
        debug!("Filesystem dumped. Finishing dumping processes");

        // Wait for checkpoint to complete
        pgrp.wait_for_success()?;

        let stats = img_streamer_progress.wait_for_stats()?;
        stats.show();
        Ok(stats)
    }().map_err(|e| {
        // Something went sideways while checkpointing (reading the file system?
        // uploading?). We SIGCONT the application if CRIU had
        // succeeded, this way we leave the application the way we found it.
        if pgrp.terminate().is_ok() &&
           pgrp.get_mut(criu_ps).wait().map_or(false, |r| r.success()) {
            debug!("Resuming application");
            let _ = kill_process_tree(Pid::from_raw(APP_ROOT_PID), signal::SIGCONT);
        } else { match get_proc_state(Pid::from_raw(APP_ROOT_PID)) {
            Ok('T') => { // STOPPED
                // CRIU failed, and the app is still in a STOPPED state.
                // We don't want to resume the app as it could be corrupted.
                warn!("The application may be in a bad state. Leaving the application STOPPED");
                warn!("You may terminate the application");
            }
            Ok(_) => {
                // CRIU failed probably due to failing to write the checkpoint
                // image. It already resumed the application.
                debug!("The application was resumed by CRIU");
            }
            Err(_) => warn!("The application state is unknown")
        }}
        e
    })?;

    if leave_running {
        debug!("Resuming application");
        kill_process_tree(Pid::from_raw(APP_ROOT_PID), signal::SIGCONT)
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

    info!("Checkpoint completed in {:.1}s", START_TIME.elapsed().as_secs_f64());

    Ok(stats)
}

impl super::CLI for Checkpoint {
    fn run(self) -> Result<()> {
        container::maybe_nsenter_app(self.app_name.as_ref())?;

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
                kill_process_tree(Pid::from_raw(APP_ROOT_PID), signal::SIGKILL)
                    .context("Failed to kill application")?;
            }

            Ok(())
        })
    }
}
