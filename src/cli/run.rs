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
    time::{SystemTime, Duration},
    ffi::OsString,
    path::PathBuf,
    fs, collections::HashSet
};
use nix::{
    sys::signal::{self, kill, SigmaskHow, SigSet},
    sys::wait::{wait, WaitStatus},
    unistd::Pid,
};
use structopt::StructOpt;
use serde::{Serialize, Deserialize};
use signal::{pthread_sigmask, Signal};
use crate::{
    consts::*,
    store::{self, Store},
    virt,
    cli::ExitCode,
    image::{ManifestFetchResult, ImageManifest, shard, check_passphrase_file_exists},
    process::{Command, CommandPidExt, ProcessExt, ProcessGroup, Stdio,
              spawn_set_ns_last_pid_server, set_ns_last_pid, MIN_PID},
    metrics::{with_metrics, with_metrics_raw, metrics_error_json},
    signal::kill_process_tree,
    util::JsonMerge,
    filesystem,
    image_streamer::{Stats, ImageStreamer},
    lock::with_checkpoint_restore_lock,
    criu,
};
use libc::c_int;
use virt::time::Nanos;


/// Run application. If a checkpoint image exists, the application is restored. Otherwise, the
/// application is run from scratch.
#[derive(StructOpt, PartialEq, Debug, Serialize)]
#[structopt(after_help("\
ENVS:
    FF_APP_PATH                 The PATH to use for the application
    FF_APP_LD_LIBRARY_PATH      The LD_LIBRARY_PATH to use for the application
    FF_APP_VIRT_CPUID_MASK      The CPUID mask to use. See libvirtcpuid documentation for more details
    FF_APP_INJECT_<VAR_NAME>    Additional environment variables to inject to the application and its children.
                                For example, FF_APP_INJECT_LD_PRELOAD=/opt/lib/libx.so
    FF_METRICS_RECORDER         When specified, FastFreeze invokes the specified program to report metrics.
                                The metrics are formatted in JSON and passed as first argument
    CRIU_OPTS                   Additional arguments to pass to CRIU, whitespace separated
    S3_CMD                      Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD                      Command to access Google Storage. Defaults to 'gsutil'
    TAR_CMD                     Command to untar the file system. Defaults to 'tar'

EXIT CODES:
    171          A failure happened during restore, or while fetching the image manifest.
                 Retrying with --no-restore will avoid that failure
    170          A failure happened before the application was ready
    128+sig_nr   The application caught a fatal signal corresponding to `sig_nr`
    exit_code    The application exited with `exit_code`"
))]
pub struct Run {
    /// Image URL. S3, GCS and local filesystem are supported: {n}
    ///   * s3://bucket_name/image_path {n}
    ///   * gs://bucket_name/image_path {n}
    ///   * file:image_path
    // {n} means new line in the CLI's --help command
    #[structopt(long, name="url")]
    image_url: String,

    /// Application arguments, used when running the app from scratch.
    /// Ignored during restore.
    // Note: Type should be OsString, but structopt doesn't like it
    #[structopt()]
    app_args: Vec<String>,

    /// Shell command to run once the application is running.
    // Note: Type should be OsString, but structopt doesn't like it
    #[structopt(long="on-app-ready", name="cmd")]
    on_app_ready_cmd: Option<String>,

    /// Always run the app from scratch. Useful to ignore a faulty image.
    #[structopt(long)]
    no_restore: bool,

    /// Allow restoring of images that don't match the version we expect.
    #[structopt(long)]
    allow_bad_image_version: bool,

    /// Provide a file containing the passphrase to be used for encrypting
    /// or decrypting the image. For security concerns, using a ramdisk
    /// like /dev/shm to store the passphrase file is preferable.
    #[structopt(long)]
    passphrase_file: Option<PathBuf>,

    /// Dir/file to include in the checkpoint image.
    /// May be specified multiple times. Multiple paths can also be specified colon separated.
    // require_delimiter is set to avoid clap's non-standard way of accepting lists.
    #[structopt(long="preserve-path", name="path", require_delimiter=true, value_delimiter=":")]
    preserved_paths: Vec<PathBuf>,

    /// Leave application stopped after restore, useful for debugging.
    /// Has no effect when running the app from scratch.
    #[structopt(long)]
    leave_stopped: bool,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Used for testing, not for normal use.
    /// App monitoring is skipped: FastFreeze exits as soon as the app is running
    // Maybe we could explore this feature at some point instead of having the
    // start hook. It might be tricky to figure out who should be the parent of
    // app during restore. We could explore CLONE_PARENT. But we would need to do similar
    // tricks to what CRIU does to monitor the process, which is to use ptrace.
    #[structopt(long, hidden=true)]
    detach: bool,
}

/// `AppConfig` is created during the run command, and updated during checkpoint.
/// These settings are saved under `APP_CONFIG_PATH`.
/// It's useful for the checkpoint command to know the image_url and preserved_paths.
/// During restore, it is useful to read the app_clock.
#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    pub image_url: String,
    pub preserved_paths: HashSet<PathBuf>,
    pub passphrase_file: Option<PathBuf>,
    pub app_clock: Nanos,
    // Used to compute the duration between a restore and a checkpoint, for metrics only.
    pub created_at: SystemTime,
}

impl AppConfig {
    pub fn save(&self) -> Result<()> {
        serde_json::to_writer_pretty(fs::File::create(&*APP_CONFIG_PATH)?, &self)?;
        Ok(())
    }

    pub fn restore() -> Result<AppConfig> {
        let file = fs::File::open(&*APP_CONFIG_PATH)
            .with_context(|| format!("Failed to open {}. \
                It is created during the run command", APP_CONFIG_PATH.display()))?;
        Ok(serde_json::from_reader(file)?)
    }
}


// It returns Stats, that's the transfer speeds and all given by criu-image-streamer,
// and the duration since the checkpoint happened. This is helpful for emitting metrics.
fn restore(
    image_url: String,
    mut preserved_paths: HashSet<PathBuf>,
    passphrase_file: Option<PathBuf>,
    shard_download_cmds: Vec<String>,
    leave_stopped: bool,
) -> Result<(Stats, Duration)> {
    info!("Restoring application{}", if leave_stopped { " (leave stopped)" } else { "" });
    let mut pgrp = ProcessGroup::new()?;

    let mut img_streamer = ImageStreamer::spawn_serve(shard_download_cmds.len())?;
    img_streamer.process.join(&mut pgrp);

    // Spawn the download processes connected to the image streamer's input
    for (download_cmd, shard_pipe) in shard_download_cmds.into_iter().zip(img_streamer.shard_pipes) {
        Command::new_shell(&download_cmd)
            .stdout(Stdio::from(shard_pipe))
            .enable_stderr_logging("download shard")
            .spawn()?
            .join(&mut pgrp);
    }

    debug!("Restoring filesystem");
    filesystem::untar_cmd(img_streamer.tar_fs_pipe.unwrap())
        .enable_stderr_logging("untar")
        .spawn()?
        .join(&mut pgrp);
    // We want to wait for tar to complete successfully. But if tar errors,
    // we want to report the errors of tar and all other processes involved.
    // The easiest way to use the process group.
    pgrp.last_mut().unwrap().wait()?; // wait on tar to finish
    pgrp.try_wait_for_success()?; // if tar errored, this is where we exit.
    debug!("Filesystem restored");

    // Because the tar command can be overridden by the user via TAR_CMD,
    // it may consume many pids. Later, when we invoke the "criu restore" tool,
    // we must ensure that its PID is lower than APP_ROOT_PID, otherwise it could
    // clash with itself.
    // We set ns_last_pid to APP_ROOT_PID-100 to balance performance and safety:
    // too low, and we might have to do a PID round trip over pid_max, too high and
    // we risk set_ns_last_pid and criu to go over APP_ROOT_PID if they are invoked via
    // bash scripts that do interesting things.
    // Note that later, we check that criu's pid is indeed lower than APP_ROOT_PID.
    set_ns_last_pid(APP_ROOT_PID-100)?;

    // The file system is back, including the application configuration containing user-defined
    // preserved-paths, and application time offset.
    // We load the app config, add the new preserved_paths, and save it.
    // It will be useful for the subsequent checkpoints.
    // Also, we keep the passphrase_file setting if there's one to ensure that
    // a previously encrypted image remains encrypted. This is normally unecessary, because
    // if the image was in fact encrypted, we would be using a passphrase_file already.
    let duration_since_checkpoint = {
        let old_config = AppConfig::restore()?;
        preserved_paths.extend(old_config.preserved_paths);
        let passphrase_file = passphrase_file.or(old_config.passphrase_file);

        let config = AppConfig {
            image_url,
            preserved_paths,
            passphrase_file,
            created_at: SystemTime::now(),
            app_clock: old_config.app_clock,
        };
        config.save()?;

        // old_config.created contains the date when checkpoint happened.
        // It is a wall clock time coming from another machine.
        // The duration between restore and checkpoint can therefore be inaccurate, and negative.
        // we'll clamp these negative values to 0.
        let restore_started_at = SystemTime::now() - START_TIME.elapsed();
        let duration_since_checkpoint = restore_started_at.duration_since(old_config.created_at)
            .unwrap_or(Duration::new(0,0));
        debug!("Duration between restore and checkpoint: {:.1}s", duration_since_checkpoint.as_secs_f64());

        // Adjust the libtimevirt offsets
        // Note that we do not add the duration_since_checkpoint to the clock.
        // The man page of clock_gettime(2) says that CLOCK_MONOTONIC "does not
        // count time that the system is suspended."
        // The man page says that CLOCK_BOOTTIME is supposed to be the one that
        // includes the duration when the system was suspended.
        // For now, we don't worry much about the semantics of CLOCK_BOOTTIME.
        // Rare are the applications that use it.
        debug!("Application clock: {:.1}s",
            Duration::from_nanos(old_config.app_clock as u64).as_secs_f64());
        virt::time::ConfigPath::default().adjust_timespecs(old_config.app_clock)?;

        duration_since_checkpoint
    };

    // We start the ns_last_pid daemon here. Note that we join_as_daemon() instead of join(),
    // this is so we don't wait for it in wait_for_success().
    debug!("Starting set_ns_last_pid server");
    spawn_set_ns_last_pid_server()?
        .join_as_daemon(&mut pgrp);

    debug!("Continuing reading image in memory...");

    // `check_pgrp_err()` is useful to report the process group error,
    // which is a more interesting error to report than the error of wait_for_stats(),
    // (which would typically be a pipe read error)
    let mut check_pgrp_err = |err| {
        if let Err(e) = pgrp.try_wait_for_success() { e }
        else { err }
    };

    let stats = img_streamer.progress.wait_for_stats()
        .map_err(&mut check_pgrp_err)?;
    stats.show();

    // Wait for the CRIU socket to be ready.
    img_streamer.progress.wait_for_socket_init()
        .map_err(&mut check_pgrp_err)?;

    // Restore application processes.
    // We become the parent of the application as CRIU is configured to use CLONE_PARENT.
    debug!("Restoring processes");
    criu::criu_restore_cmd(leave_stopped)
        .enable_stderr_logging("criu")
        .spawn()
        .and_then(|ps| {
            ensure!(ps.pid() < APP_ROOT_PID, "CRIU's pid is too high: {}", ps.pid());
            Ok(ps)
        })?
        .join(&mut pgrp);

    // Wait for all our all our monitored processes to finish.
    // If there's an issue, kill the app if it's still laying around.
    // We might want to check that we are the parent of the process with pid APP_ROOT_PID,
    // otherwise, we might be killing an innocent process. But that would be racy anyways.
    if let Err(e) = pgrp.wait_for_success() {
        let _ = kill_process_tree(APP_ROOT_PID, signal::SIGKILL);
        return Err(e);
    }

    info!("Application is ready, restore took {:.1}s", START_TIME.elapsed().as_secs_f64());

    Ok((stats, duration_since_checkpoint))
}

/// `monitor_app()` assumes the init role. We do the following:
/// 1) We proxy signals we receive to our child pid=APP_ROOT_PID.
/// 2) We reap processes that get reparented to us.
/// 3) When APP_ROOT_PID dies, we return an error that contains the appropriate exit_code.
fn monitor_app() -> Result<()> {
    match monitor_app_inner() {
        Err(e) if ExitCode::from_error(&e) == 0 => Ok(()),
        other => other,
    }
}
fn monitor_app_inner() -> Result<()> {
    for sig in Signal::iterator() {
        // We don't forward SIGCHLD, and neither `FORBIDDEN` signals (e.g.,
        // SIGSTOP, SIGFPE, SIGKILL, ...)
        if sig == Signal::SIGCHLD || signal_hook::FORBIDDEN.contains(&(sig as c_int)) {
            continue;
        }

        // Forward signal to our child.
        // The `register` function is unsafe because one could call malloc(),
        // and deadlock the program. Here we call kill() which is safe.
        unsafe {
            signal_hook::register(sig as c_int, move || {
                let _ = kill(Pid::from_raw(APP_ROOT_PID), sig);
            })?;
        }
    }
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&SigSet::all()), None)?;

    // Helper function used in the loop
    fn child_exited<F: Fn() -> anyhow::Error>(pid: Pid, app_exited_f: F) -> Result<()> {
        if pid.as_raw() == APP_ROOT_PID {
            // kill remaining orphans: They belong to the process group that we
            // made with setsid() in run_from_scratch().
            // TODO Check if that's actually necessary.
            let _ = kill_process_tree(APP_ROOT_PID, signal::SIGKILL);
            Err(app_exited_f())
        } else {
            Ok(())
        }
    }

    loop {
        match wait()? {
            WaitStatus::Exited(pid, exit_status) =>
                child_exited(pid, || {
                    anyhow!("Application exited with exit_code={}", exit_status)
                        .context(ExitCode(exit_status as u8))
                })?,
            WaitStatus::Signaled(pid, signal, _core_dumped) =>
                child_exited(pid, || {
                    anyhow!("Application caught fatal signal {}", signal)
                        .context(ExitCode(128 + signal as u8))
                })?,
            _ => {},
        };
    }
}

fn run_from_scratch(
    image_url: String,
    preserved_paths: HashSet<PathBuf>,
    passphrase_file: Option<PathBuf>,
    app_cmd: Vec<OsString>,
) -> Result<()>
{
    let config = AppConfig {
        image_url,
        preserved_paths,
        passphrase_file,
        app_clock: 0,
        created_at: SystemTime::now(),
    };
    config.save()?;

    virt::time::ConfigPath::default().write_intial()?;
    virt::enable_system_wide_virtualization()?;

    let mut cmd = Command::new(app_cmd);
    if let Some(path) = std::env::var_os("FF_APP_PATH") {
        cmd.env_remove("FF_APP_PATH")
           .env("PATH", path);
    }
    if let Some(library_path) = std::env::var_os("FF_APP_LD_LIBRARY_PATH") {
        cmd.env_remove("FF_APP_LD_LIBRARY_PATH")
           .env("LD_LIBRARY_PATH", library_path);
    }
    cmd.setsid();
    cmd.spawn_with_pid(APP_ROOT_PID)?;

    info!("Application is ready, started from scratch");

    Ok(())
}

pub enum RunMode {
    Restore { img_manifest: ImageManifest },
    FromScratch,
}

pub fn determine_run_mode(store: &dyn Store, allow_bad_image_version: bool) -> Result<RunMode> {
    let fetch_result = with_metrics("fetch_manifest",
        || ImageManifest::fetch_from_store(store, allow_bad_image_version),
        |fetch_result| match fetch_result {
            ManifestFetchResult::Some(_)              => json!({"manifest": "good",             "run_mode": "restore"}),
            ManifestFetchResult::VersionMismatch {..} => json!({"manifest": "version_mismatch", "run_mode": "run_from_scratch"}),
            ManifestFetchResult::NotFound             => json!({"manifest": "not_found",        "run_mode": "run_from_scratch"}),
        }
    )?;

    Ok(match fetch_result {
        ManifestFetchResult::Some(img_manifest) => {
            debug!("Image manifest found: {}", img_manifest);
            RunMode::Restore { img_manifest }
        }
        ManifestFetchResult::VersionMismatch { fetched, desired } => {
            info!("Image manifest found, but has version {} while the expected version is {}. \
                   You may try again with --allow-bad-image-version. \
                   Running application from scratch", fetched, desired);
            RunMode::FromScratch
        }
        ManifestFetchResult::NotFound => {
            info!("Image manifest not found, running application from scratch");
            RunMode::FromScratch
        }
    })
}

fn ensure_non_conflicting_pid() -> Result<()> {
    // We don't want to use a PID that could be potentially used by the
    // application when being restored.
    if std::process::id() > APP_ROOT_PID as u32 {
        // We should be pid=1 in a container, so this code block only applies when running
        // outside of a container.
        set_ns_last_pid(MIN_PID)?;
        bail!("Current pid is too high. Re-run the same command again.");
    }

    Ok(())
}

impl super::CLI for Run {
    fn run(self) -> Result<()> {
        // We use `with_metrics` to log the exit_code of the application and run time duration
        with_metrics_raw("run", || self.run_inner(), |result|
            match result {
                Ok(()) => json!({
                    "outcome": "success",
                    "exit_code": 0,
                }),
                Err(e) => json!({
                    "outcome": "error",
                    "exit_code": ExitCode::from_error(&e),
                    "error": format!("{:#}", e),
                }).merge(metrics_error_json(e))
            }
        )
    }
}

impl Run {
    fn run_inner(self) -> Result<()> {
        let Self {
            image_url, app_args, on_app_ready_cmd, no_restore,
            allow_bad_image_version, passphrase_file, preserved_paths,
            leave_stopped, verbose: _, detach } = self;

        let preserved_paths = preserved_paths.into_iter().collect();
        if let Some(ref passphrase_file) = passphrase_file {
            check_passphrase_file_exists(passphrase_file)?;
        }

        // Holding the lock while invoking any process (e.g., `criu_check_cmd`) is
        // preferrable to avoid disturbing another instance of FastFreeze trying
        // to do PID control.
        with_checkpoint_restore_lock(|| {
            criu::criu_check_cmd()
                .enable_stderr_logging("criu-check")
                .spawn()?
                .wait_for_success()?;

            ensure_non_conflicting_pid()?;

            // We prepare the store for writes to speed up checkpointing. Notice that
            // we also prepare the store during restore, because we want to make sure
            // we can checkpoint after a restore.
            trace!("Preparing image store");
            let store = store::from_url(&image_url)?;
            store.prepare(true)?;

            let run_mode = if no_restore {
                info!("Running app from scratch as specified with --no-restore");
                RunMode::FromScratch
            } else {
                info!("Fetching image manifest for {}", image_url);
                determine_run_mode(&*store, allow_bad_image_version)
                    .context(ExitCode(EXIT_CODE_RESTORE_FAILURE))?
            };

            match run_mode {
                RunMode::Restore { img_manifest } => {
                    let shard_download_cmds = shard::download_cmds(
                        &img_manifest, passphrase_file.as_ref(), &*store)?;

                    with_metrics("restore", ||
                        restore(
                            image_url, preserved_paths, passphrase_file,
                            shard_download_cmds, leave_stopped
                        ).context(ExitCode(EXIT_CODE_RESTORE_FAILURE)),
                        |(stats, duration_since_checkpoint)|
                            json!({
                                "stats": stats,
                                "duration_since_checkpoint_sec": duration_since_checkpoint.as_secs_f64(),
                            })
                        )?;
                }
                RunMode::FromScratch => {
                    let app_args = app_args.into_iter().map(|s| s.into()).collect();
                    with_metrics("run_from_scratch", ||
                        run_from_scratch(image_url, preserved_paths, passphrase_file, app_args),
                        |_| json!({}))?;
                }
            }

            Ok(())
        })?;

        if let Some(on_app_ready_cmd) = on_app_ready_cmd {
            // Fire and forget.
            Command::new_shell(&on_app_ready_cmd)
                .spawn()?;
        }

        // detach is only used for integration tests
        if !detach {
            monitor_app()?;
        }

        Ok(())
    }
}
