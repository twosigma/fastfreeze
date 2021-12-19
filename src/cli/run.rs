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
    io::{BufReader, BufWriter},
    collections::HashSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, Duration}
};
use nix::{
    sys::signal,
    unistd::Pid,
};
use structopt::StructOpt;
use serde::{Serialize, Deserialize};
use crate::{
    consts::*,
    store::{ImageUrl, Store},
    virt,
    cli::ExitCode,
    image::{ManifestFetchResult, ImageManifest, shard, check_passphrase_file_exists},
    process::{Command, CommandPidExt, ProcessExt, ProcessGroup, Stdio,
              spawn_set_ns_last_pid_server, set_ns_last_pid, monitor_child, MIN_PID},
    metrics::{with_metrics, with_metrics_raw, metrics_error_json},
    signal::kill_process_tree,
    util::JsonMerge,
    filesystem,
    image_streamer::{Stats, ImageStreamer},
    lock::with_checkpoint_restore_lock,
    container,
    criu,
};


/// Run application.
/// If a checkpoint image exists, the application is restored. Otherwise, the
/// application is run from scratch.
#[derive(StructOpt, PartialEq, Debug, Serialize)]
#[structopt(after_help("\
ENVS:
    FF_APP_VIRT_CPUID_MASK         The CPUID mask to use. See libvirtcpuid documentation for more details
    FF_APP_VIRT_TIME_IN_USERSPACE  When set to 1, kernel time namespaces won't be used
                                   This is useful to restore on older hosts (kernel 5.5 and lower)
    FF_APP_PATH                    The PATH to use for the application
    FF_APP_LD_LIBRARY_PATH         The LD_LIBRARY_PATH to use for the application
    FF_APP_INJECT_<VAR_NAME>       Additional environment variables to inject to the application and its children.
                                   For example, FF_APP_INJECT_LD_PRELOAD=/opt/lib/libx.so
    FF_METRICS_CMD                 When specified, FastFreeze invokes the specified program to report metrics.
                                   The metrics are formatted in JSON and passed as first argument
    FF_FAKE_ROOT                   Setting to 1 instructs FastFreeze to use uid=0 when creating user namespaces
    CRIU_OPTS                      Additional arguments to pass to CRIU, whitespace separated
    S3_CMD                         Command to access AWS S3. Defaults to 'aws s3'
    GS_CMD                         Command to access Google Storage. Defaults to 'gcsthin'
    TAR_CMD                        Command to untar the file system. Defaults to 'tar'

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
    /// It defaults to file:$HOME/.fastfreeze/<app_name>
    // {n} means new line in the CLI's --help command
    #[structopt(short, long, name="url")]
    image_url: Option<String>,

    /// Application command, used when running the app from scratch.
    /// When absent, FastFreeze runs in restore-only mode.
    #[structopt()]
    app_args: Vec<OsString>,

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

    /// Remap the TCP listen socket ports during restore.
    /// Format is old_port:new_port.
    /// Multiple tcp port remaps may be passed as a comma separated list.
    // We use String because we just pass the argument directly to criu-image-streamer.
    #[structopt(long, require_delimiter = true)]
    tcp_listen_remap: Vec<String>,

    /// Leave application stopped after restore, useful for debugging.
    /// Has no effect when running the app from scratch.
    #[structopt(long)]
    leave_stopped: bool,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Specify the application name. This is used to distinguish applications
    /// when running multiple ones. The default is the file name of the image-url.
    /// Note: application specific files are located in /tmp/fastfreeze/<app_name>.
    #[structopt(short="n", long)]
    app_name: Option<String>,
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
    // Used to compute the duration between a restore and a checkpoint, for metrics only.
    pub created_at: SystemTime,
    // When we pass external pipes to the application as stdin/stdout/stderr,
    // we need to remember the pipe inodes that we passed, so that when we restore,
    // we can replace the original external pipes by the new ones.
    pub inherited_resources: criu::InheritableResources,
    // Virtualization configuration. This needs to be identical across checkpoint/restore.
    pub virt_config: virt::Config,
}

impl AppConfig {
    pub fn save(&self) -> Result<()> {
        let file = fs::File::create(&*APP_CONFIG_PATH)
            .with_context(|| format!("Failed to create {}", APP_CONFIG_PATH.display()))?;
        let file = BufWriter::new(file);
        serde_json::to_writer_pretty(file, &self)?;
        Ok(())
    }

    pub fn restore() -> Result<AppConfig> {
        let file = fs::File::open(&*APP_CONFIG_PATH)
            .with_context(|| format!("Failed to open {}. \
                It is created during the run command", APP_CONFIG_PATH.display()))?;
        let file = BufReader::new(file);
        Ok(serde_json::from_reader(file)?)
    }

    pub fn exists() -> bool {
        APP_CONFIG_PATH.exists()
    }

    pub fn remove() -> Result<()> {
        fs::remove_file(&*APP_CONFIG_PATH)
            .with_context(|| format!("Failed to remove {}", APP_CONFIG_PATH.display()))
    }
}

pub fn is_app_running() -> bool {
    AppConfig::exists() &&
        Path::new("/proc").join(APP_ROOT_PID.to_string()).exists()
}


// It returns Stats, that's the transfer speeds and all given by criu-image-streamer,
// and the duration since the checkpoint happened. This is helpful for emitting metrics.
fn restore(
    privileges: container::Privileges,
    image_url: ImageUrl,
    mut preserved_paths: HashSet<PathBuf>,
    tcp_listen_remaps: Vec<String>,
    passphrase_file: Option<PathBuf>,
    shard_download_cmds: Vec<String>,
    leave_stopped: bool,
) -> Result<(Stats, Duration)> {
    info!("Restoring application{}", if leave_stopped { " (leave stopped)" } else { "" });
    let mut pgrp = ProcessGroup::new()?;

    let mut img_streamer = ImageStreamer::spawn_serve(shard_download_cmds.len(), tcp_listen_remaps)?;
    img_streamer.process.join(&mut pgrp);

    // Spawn the download processes connected to the image streamer's input
    for (i, (download_cmd, shard_pipe)) in shard_download_cmds.into_iter().zip(img_streamer.shard_pipes).enumerate() {
        Command::new_shell(&download_cmd)
            .stdout(Stdio::from(shard_pipe))
            .enable_stderr_logging(format!("download shard {}", i))
            .spawn()?
            .join(&mut pgrp);
    }

    debug!("Restoring filesystem");
    let untar_ps = filesystem::untar_cmd(img_streamer.tar_fs_pipe.unwrap())
        .enable_stderr_and_stdout_logging("untar") // Important, untar vebose prints on stdout.
        .spawn()?
        .join(&mut pgrp);
    // We want to wait for tar to complete successfully. But if tar errors,
    // we want to report the errors of tar and all other processes involved.
    // The easiest way to use the process group.
    pgrp.get_mut(untar_ps).wait()?; // wait for tar to finish
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
    let (duration_since_checkpoint, skip_timens, previously_inherited_resources) = {
        let old_config = AppConfig::restore()?;
        preserved_paths.extend(old_config.preserved_paths);
        let passphrase_file = passphrase_file.or(old_config.passphrase_file);

        let previously_inherited_resources = old_config.inherited_resources;
        let current_inherited_resources = criu::InheritableResources::current()?;
        ensure!(previously_inherited_resources.compatible_with(&current_inherited_resources),
            "Cannot match the original application file descriptors patterns. \
             Try again by connecting file descriptors such that they are grouped in a similar manner. \n\
             Original file descriptors: {:#?},\n\
             Current file descriptors: {:#?}",
            previously_inherited_resources.0, current_inherited_resources.0);

        trace!("Virtualization {:#?}", &old_config.virt_config);
        virt::ensure_sufficient_privileges_for_restore(&old_config.virt_config, &privileges)?;
        virt::enable_for_restore(&old_config.virt_config)?;

        // old_config.created contains the date when checkpoint happened.
        // It is a wall clock time coming from another machine.
        // The duration between restore and checkpoint can therefore be inaccurate, and negative.
        // we'll clamp these negative values to 0.
        let restore_started_at = SystemTime::now() - START_TIME.elapsed();
        let duration_since_checkpoint = restore_started_at.duration_since(old_config.created_at)
            .unwrap_or_else(|_| Duration::new(0,0));
        debug!("Duration between restore and checkpoint: {:.1}s", duration_since_checkpoint.as_secs_f64());

        let skip_timens = old_config.virt_config.use_libvirttime();

        AppConfig {
            image_url: image_url.to_string(),
            preserved_paths,
            passphrase_file,
            created_at: SystemTime::now(),
            inherited_resources: current_inherited_resources,
            virt_config: old_config.virt_config,
        }.save()?;

        (duration_since_checkpoint, skip_timens, previously_inherited_resources)
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
    criu::criu_restore_cmd(leave_stopped, skip_timens, &previously_inherited_resources)
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
        let _ = kill_process_tree(Pid::from_raw(APP_ROOT_PID), signal::SIGKILL);
        return Err(e);
    }

    info!("Application is ready, restore took {:.1}s", START_TIME.elapsed().as_secs_f64());

    Ok((stats, duration_since_checkpoint))
}

fn run_from_scratch(
    privileges: container::Privileges,
    image_url: ImageUrl,
    preserved_paths: HashSet<PathBuf>,
    passphrase_file: Option<PathBuf>,
    app_cmd: Vec<OsString>,
) -> Result<()>
{
    ensure!(!app_cmd.is_empty(), "Error: application command must be specified");

    let inherited_resources = criu::InheritableResources::current()?;

    // expect() because we already checked that we could get the virtualization
    // config within privileges.ensure_sufficient_privileges().
    let virt_config = virt::get_initial_virt_config(&privileges)
        .expect("virtualization logic error");
    trace!("Virtualization {:#?}", virt_config);

    // The following takes care of the time virtualization setup.
    // We don't use CRIU's time virtualization support because we prefer to
    // provide the application an app clock that starts at 0s.
    virt::enable_for_the_first_time(&virt_config)?;

    let config = AppConfig {
        image_url: image_url.to_string(),
        preserved_paths,
        passphrase_file,
        created_at: SystemTime::now(),
        inherited_resources,
        virt_config,
    };
    config.save()?;

    let mut cmd = Command::new(app_cmd);
    if let Some(path) = std::env::var_os("FF_APP_PATH") {
        cmd.env_remove("FF_APP_PATH")
           .env("PATH", path);
    }
    if let Some(library_path) = std::env::var_os("FF_APP_LD_LIBRARY_PATH") {
        cmd.env_remove("FF_APP_LD_LIBRARY_PATH")
           .env("LD_LIBRARY_PATH", library_path);
    }

    cmd.env("FASTFREEZE", "1");

    // We want to give the application a /tmp that we'll include in our image,
    // but we can't just mount bind it on /tmp. That's because it would be confusing
    // for users when trying to exchange files from the host to the containered app
    // via /tmp (for example when using Jupyter notebooks).
    // Setting TMPDIR to an empty directory in the fastfreeze directory is a
    // good compromise.
    cmd.env("TMPDIR", &*CONTAINER_APP_TMP);

    // We don't set the application in a process group because we want to be
    // compatible with both of these usages:
    // * "cat | fastfreeze run cat": the first cat must be in the process group
    // controlling the terminal to receive input
    // * "fastfreeze run cat": the cat here must be in the process group
    // controlling the terminal
    // We don't want to create a new process group as this would remove any
    // hopes in making both scenarios work well.

    // When an application process die, its children are normally reparented to
    // the init process. These children become invisible from CRIU as they are no
    // longer belonging in the application's process tree. That's bad news.
    // We set the application root process to be a child subreaper, as opposed to init.
    // This way we won't loose children.
    cmd.set_child_subreaper();

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
            ManifestFetchResult::Some(_) =>
                json!({"manifest": "good", "run_mode": "restore"}),
            ManifestFetchResult::VersionMismatch {..} =>
                json!({"manifest": "version_mismatch", "run_mode": "run_from_scratch"}),
            ManifestFetchResult::NotFound =>
                json!({"manifest": "not_found", "run_mode": "run_from_scratch"}),
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
            debug!("Image manifest not found, running application from scratch");
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

fn do_run(
    privileges: container::Privileges,
    image_url: ImageUrl,
    app_args: Option<Vec<OsString>>,
    preserved_paths: HashSet<PathBuf>,
    tcp_listen_remaps: Vec<String>,
    passphrase_file: Option<PathBuf>,
    no_restore: bool,
    allow_bad_image_version: bool,
    leave_stopped: bool,
) -> Result<()> {
    // Holding the `with_checkpoint_restore_lock` lock (done by caller) while
    // invoking any process (e.g., `criu_check_cmd`) is preferrable to avoid
    // disturbing another instance of FastFreeze trying to do PID control.
    criu::criu_check_cmd()
        .enable_stderr_logging("criu-check")
        .spawn()?
        .wait_for_success()?;

    ensure_non_conflicting_pid()?;

    // We prepare the store for writes to speed up checkpointing. Notice that
    // we also prepare the store during restore, because we want to make sure
    // we can checkpoint after a restore.
    trace!("Preparing image store");
    let store = image_url.store();
    store.prepare(true)?;

    let run_mode = if no_restore {
        debug!("Running app from scratch (--no-restore)");
        RunMode::FromScratch
    } else {
        debug!("Fetching image manifest for {}", image_url);
        determine_run_mode(&*store, allow_bad_image_version)
            .context(ExitCode(EXIT_CODE_RESTORE_FAILURE))?
    };

    match (run_mode, app_args) {
        (RunMode::Restore { img_manifest }, _) => {
            let shard_download_cmds = shard::download_cmds(
                &img_manifest, passphrase_file.as_ref(), &*store)?;

            with_metrics("restore", ||
                restore(
                    privileges,
                    image_url, preserved_paths, tcp_listen_remaps,
                    passphrase_file, shard_download_cmds, leave_stopped
                ).context(ExitCode(EXIT_CODE_RESTORE_FAILURE)),
                |(stats, duration_since_checkpoint)|
                    json!({
                        "stats": stats,
                        "duration_since_checkpoint_sec": duration_since_checkpoint.as_secs_f64(),
                    })
                )?;
        }
        (RunMode::FromScratch, None) =>
            bail!("No application to restore, but running in restore-only mode, aborting"),
        (RunMode::FromScratch, Some(app_args)) => {
            let app_args = app_args.into_iter().collect();
            with_metrics("run_from_scratch", ||
                run_from_scratch(privileges, image_url, preserved_paths, passphrase_file, app_args),
                |_| json!({}))?;
        }
    }

    Ok(())
}

fn default_image_name(app_args: &[OsString]) -> Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn program_name(cmd: &OsString) -> Result<String> {
        Ok(Path::new(cmd)
            .file_name().ok_or_else(||
                anyhow!("Failed to determine program name from command name. \
                         Please use `--image-url` to specify the image URL"))?
            .to_string_lossy().into_owned())
    }

    Ok(match app_args {
        [] => unreachable!(),
        [app_name] => program_name(app_name)?,
        _ =>  {
            let hash = {
                let mut hasher = DefaultHasher::new();
                app_args.hash(&mut hasher);
                hasher.finish()
            };

            format!("{}-{:04x}", program_name(&app_args[0])?, hash & 0xFFFF)
        }
    })
}

impl super::CLI for Run {
    fn run(self) -> Result<()> {
        let inner = || -> Result<()> {
            let Self {
                image_url, app_args, on_app_ready_cmd, no_restore,
                allow_bad_image_version, passphrase_file, preserved_paths,
                tcp_listen_remap, leave_stopped, verbose: _, app_name } = self;

            // We allow app_args to be empty. This indicates a restore-only mode.
            let app_args = if app_args.is_empty() {
                info!("Running in restore-only mode as no command is given");
                None
            } else {
                ensure!(!app_args[0].is_empty(), "Empty command given");
                Some(app_args)
            };


            let image_url = match (image_url, app_args.as_ref()) {
                (Some(image_url), _) => image_url,
                (None, None) =>
                    bail!("--image-url is necessary when running in restore-only mode"),
                (None, Some(app_args)) => {
                    let image_path = DEFAULT_IMAGE_DIR.join(default_image_name(app_args)?);
                    let image_url = format!("file:{}", image_path.display());
                    info!("image-url is {}", image_url);
                    image_url
                }
            };
            let image_url = ImageUrl::parse(&image_url)?;

            let privileges = container::Privileges::detect()?;
            trace!("{:#?}", privileges);
            privileges.ensure_sufficient_privileges()?;

            let app_name = match privileges.ensure_mutiple_apps_support() {
                Ok(()) => {
                    Some(app_name
                        .as_deref()
                        .unwrap_or_else(|| image_url.image_name()))
                }
                Err(e) => {
                    // We don't have support for named containers.
                    // Only one application can run at a time.
                    ensure!(app_name.is_none(), "`--app-name <NAME>` cannot be used as {}", e);
                    None
                }
            };

            // We enter the named container immediately. This is so our
            // /var/tmp/fastfreeze path points to the
            // /tmp/fastfreeze/<app_name> directory.  This matters because
            // we are about to call with_checkpoint_restore_lock()
            // below, which grabs a lock located in /var/tmp/fastfreeze.

            // Note: the following forks a child to enter the new PID namespace.
            // The parent will be kept running to monitor the child.
            // The execution continues as the child process.
            container::create(&privileges, app_name)?;

            if let Some(ref passphrase_file) = passphrase_file {
                check_passphrase_file_exists(passphrase_file)?;
            }

            let preserved_paths = preserved_paths.into_iter().collect();

            with_checkpoint_restore_lock(|| do_run(
                privileges,
                image_url, app_args, preserved_paths, tcp_listen_remap,
                passphrase_file, no_restore, allow_bad_image_version,
                leave_stopped))?;

            if let Some(on_app_ready_cmd) = on_app_ready_cmd {
                let mut p = Command::new_shell(&on_app_ready_cmd)
                    .spawn()?;

                // We use a separate thread to monitor this process.
                // The monotoring is only used to emit log messages to help the
                // user troubleshooting when things break.
                std::thread::spawn(move || {
                    if let Err(e) = p.wait_for_success() {
                        error!("--on-app-ready command failed: {}", e);
                    }
                });
            }

            let app_exit_result = monitor_child(Pid::from_raw(APP_ROOT_PID), false);
            if app_exit_result.is_ok() {
                info!("Application exited with exit_code=0");
            }

            // The existance of the app config indicates if the app may b
            // running (see is_app_running()), so it's better to take it out.
            if let Err(e) = AppConfig::remove() {
                error!("{}, but it's okay", e);
            }

            app_exit_result
        };

        // We use `with_metrics` to log the exit_code of the application and run time duration
        with_metrics_raw("run", inner, |result|
            match result {
                Ok(()) => json!({
                    "outcome": "success",
                    "exit_code": 0,
                }),
                Err(e) => json!({
                    "outcome": "error",
                    "exit_code": ExitCode::from_error(e),
                    "error": format!("{:#}", e),
                }).merge(metrics_error_json(e))
            }
        )
    }
}
