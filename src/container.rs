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

// In non-docker and non-kubernetes environments, we can create a container
// because we don't have the /proc/sys read-only restriction.

use anyhow::{Result, Context};
use std::{
    fs,
    path::PathBuf,
    io::ErrorKind,
    path::Path,
    os::unix::io::RawFd,
    collections::HashSet,
};
use nix::{
    fcntl::{OFlag, open},
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
    sys::signal::{self, kill},
    sys::termios::tcgetattr,
    sys::stat::Mode,
    unistd::{ForkResult, Pid, dup2, fork, getgid, getuid, close}
};
use crate::{
    consts::*,
    cli::{ExitCode, install, run::is_app_running},
    process::{monitor_child, ChildDied},
    util::{create_dir_all, set_tmp_like_permissions, openat, setns},
    logger,
};

// User namespace
//////////////////////////////////

fn prepare_user_namespace() -> Result<()> {
    let uid = getuid();
    let gid = getgid();

    unshare(CloneFlags::CLONE_NEWUSER)
        .context("Failed to create user namespace")?;

    // This user namespace is important. It gives us the ability to mount /proc,
    // mount bind. We could mount /sys and tmpfs if we wanted to as well.

    // The following gives us maps our current UID to UID=0 (root) in our new
    // user namespace. This gives us CAP_SYS_ADMIN in our pid namespace.
    fs::write("/proc/self/setgroups", "deny")
        .context("Failed to write to /proc/self/setgroups")?;

    fs::write("/proc/self/uid_map", format!("0 {} 1", uid))
        .context("Failed to write to /proc/self/uid_map")?;

    fs::write("/proc/self/gid_map", format!("0 {} 1", gid))
        .context("Failed to write to /proc/self/gid_map")?;

    Ok(())
}


// FS namespace
//////////////////////////////////

fn mount_bind(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let from = from.as_ref();
    let to = to.as_ref();
    // It seems that we don't need to mount with MS_PRIVATE.
    mount(Some(from), to, None as Option<&str>, MsFlags::MS_BIND, None as Option<&str>)
        .with_context(|| format!("Failed to bind mount {} to {}", from.display(), to.display()))
}

fn prepare_fs_namespace(name: &str) -> Result<()> {
    // We create the directory that holds all the containers with /tmp-like
    // permissions to allow other users to use the same directory. It's okay if it fails
    create_dir_all(&*CONTAINERS_DIR)?;
    let _ = set_tmp_like_permissions(&*CONTAINERS_DIR);

    // We'll mount bind on FF_DIR. Its writability is not required. It can even
    // be owned by another user. Note that we probably already have this directory
    // created by the logger.
    create_dir_all(&*FF_DIR)?;

    // The mount namespace allows us to provide a private ff_dir=/var/tmp/fastfreeze
    // and hijack the system ELF loader.
    // It's also necessary for the PID namespace to provide a correct /proc mount.
    unshare(CloneFlags::CLONE_NEWNS)
        .context("Failed to create mount namespace")?;

    let private_ff_dir = CONTAINERS_DIR.join(name);
    let _ = fs::remove_dir_all(&private_ff_dir);
    create_dir_all(&private_ff_dir)?;

    // We relocate the log file in the container's log file directory.
    // This is helpful to preserve log files in checkpointed images.
    logger::move_log_file(&private_ff_dir.join("logs"))?;

    // It seems that we don't need to remount / with MS_SLAVE to make
    // our mounts private.
    mount_bind(&private_ff_dir, &*FF_DIR)?;
    install::prepare_ff_dir()?;
    mount_bind(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH)?;

    // We want to give the application a /tmp that we'll include in our image,
    // but we can't just mount bind it on /tmp. That's because it would be confusing
    // for users when trying to exchange files from the host to the containered app
    // via /tmp (for example when using Jupyter notebooks).
    // Setting TMPDIR to an empty directory is a good compromise.
    create_dir_all(&*CONTAINER_APP_TMP)?;
    let _ = set_tmp_like_permissions(&*CONTAINER_APP_TMP);
    std::env::set_var("TMPDIR", &*CONTAINER_APP_TMP);

    Ok(())
}

// PTY "namespace"
//////////////////////////////////

fn lookup_fd_path(fd: RawFd) -> Result<PathBuf> {
    let path = format!("/proc/self/fd/{}", fd);
    fs::read_link(&path)
        .with_context(|| format!("Failed to readlink {}", &path))
}

/// Returns fds among 0,1,2 that corresponds to a TTY.
pub fn get_tty_fds() -> Vec<RawFd> {
    // We examine stdin/stdout/stderr and select what responds to a TTY.
    [0,1,2].iter()
        .map(|fd| *fd)
        .filter(|fd| tcgetattr(*fd).is_ok())
        .collect()
}

// We take an array of TTY fds to ensure that they all point to the same TTY,
// but semantically, we should be taking just a single fd.
fn get_tty_path(tty_fds: &[RawFd]) -> Result<PathBuf> {
    let paths = tty_fds.iter()
        .map(|fd| *fd)
        .map(lookup_fd_path)
        .collect::<Result<HashSet<_>>>()?;

    assert!(paths.len() > 0);
    ensure!(paths.len() == 1, "Multiple TTYs detected");
    Ok(paths.into_iter().next().unwrap())
}

fn reopen_tty_fd(fd: RawFd, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let new_fd = open(path, OFlag::O_RDWR, Mode::empty())
        .with_context(|| format!("Failed to reopen {}", path.display()))?;

    dup2(new_fd, fd).context("dup2() failed")?;
    close(new_fd).context("close() failed")?;

    Ok(())
}

fn prepare_pty_namespace() -> Result<()> {
    // We need a new pts namespace during checkpoint/restore because:
    // 1) we pass the current pty (what we currently hold as stderr for example)
    //    to the child. It needs to be deterministic because when we restore, it
    //    needs to have the same name. We'll use /dev/pts/0 for passing down our pty.
    // 2) PTYs created in the container (by a program like tmux or sshd)
    //    need to be conflict free when restoring (/dev/pts/N should be available),
    //    so we need some amount of virtualization.
    // We want to mount new namespace on /dev/pts, but we want to map our current pty
    // to /dev/pts/0. We'll do some trickeries with mount binds to achieve that.
    // Another solution would be to create a new pty, and proxy data to/from our
    // current pty. But that's a bunch of pain, and not what we really want.

    // Step 1: Make a bind backup of our /dev/pts/N to CONTAINER_PTY because we are
    // about to hide it with the next mount.
    let tty_fds = get_tty_fds();
    if !tty_fds.is_empty() {
        let tty_path = get_tty_path(&tty_fds)?;
        debug!("Mapping TTY {} to /dev/pts/0", tty_path.display());
        fs::File::create(&*CONTAINER_PTY)
            .with_context(|| format!("Failed to create file {}", CONTAINER_PTY.display()))?;
        mount_bind(&tty_path, &*CONTAINER_PTY)?;
    }

    // Step 2: Make the /dev/pts namespace
    // We pass the ptmxmode=0666 option so that the permissions of /dev/ptmx is
    // accessible by all to create new PTYs, useful for applications like tmux
    // or sshd.
    // We wish to pass the options gid=5,mode=0620 (tty group) but we get
    // -EINVAL if we try, it has probably something to do with the way we map
    // our uid/gid in user_namespace(). This is not really important.
    mount(Some("devpts"), "/dev/pts", Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("ptmxmode=0666"))
        .context("Failed to mount /dev/pts")?;
    mount_bind("/dev/pts/ptmx", "/dev/ptmx")?;

    // Step 3: mount bind CONTAINER_PTY to /dev/pts/0.
    // For this to work, /dev/pts/0 must exist. So we create a dummy pts
    // that we keep open to ensure that the mount bind survives.
    // We leak the fd on purpose (not closing it).
    if !tty_fds.is_empty() {
        let _pts_0_fd = open("/dev/ptmx", OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())
            .context("Failed to open /dev/ptmx to create a dummy PTY")?;
        mount_bind(&*CONTAINER_PTY, "/dev/pts/0")?;

        // The application inherits our PTY. The /proc/self/fdinfo/<N>
        // information will show a mount id outside of the mount namespace and that
        // makes CRIU unhappy. We re-open the PTYs bringing them into our own mount
        // namespace.
        for fd in tty_fds {
            reopen_tty_fd(fd, "/dev/pts/0")?;
        }
    }

    Ok(())
}

// PID namespace
//////////////////////////////////

fn monitor_container(container_pid: Pid) {
    let result = monitor_child(container_pid);

    // The container has died. We clean up the container pid file to speed up
    // the enumeration of running containers.
    let _ = fs::remove_file(&*CONTAINER_PID);

    // We remove NO_PRESERVE_FF_DIR and other files to save a bit of space.
    // This does not remove fastfreeze logs files and the tmpdir of the
    // application. Maybe the user wants to keep these files. It's fine because
    // these files reside on /tmp, which will get eventually cleaned away by the OS.
    let _ = fs::remove_file(&*LD_INJECT_ENV_PATH);
    let _ = fs::remove_file(&*VIRT_TIME_CONF_PATH);
    let _ = fs::remove_file(&*APP_CONFIG_PATH);
    let _ = nix::mount::umount(&*CONTAINER_PTY); // to avoid EBUSY when deleting.
    let _ = fs::remove_dir_all(&*NO_PRESERVE_FF_DIR);

    if let Err(e) = result {
        // Our child logs errors when exiting, so we skip logging in this case
        match e.downcast_ref::<ChildDied>() {
            Some(ChildDied::Exited(_)) => {},
            _ => { log::error!("{:#}", e) },
        }

        let exit_code = ExitCode::from_error(&e);
        std::process::exit(exit_code as i32);
    }

    std::process::exit(0);
}

fn prepare_pid_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWPID)
        .context("Failed to create PID namespace")?;

    if let ForkResult::Parent { child: container_pid } = fork()? {
        // We write down the container init process pid. It will be useful later
        // to entering the container when checkpointing (or with nsenter).
        // If we fail, we kill the container immediately.
        fs::write(&*CONTAINER_PID, format!("{}\n", container_pid))
            .map_err(|e| { let _ = kill(container_pid, signal::SIGKILL); e })?;

        monitor_container(container_pid);
        unreachable!();
    }

    // We are now in the new PID namespace, as the init process

    // We can mount /proc because we have a root-mapped user namespace :)
    // This won't work if we are in a docker/kubernetes environment with a
    // protected /proc with a bunch of read-only subdirectory binds.
    let proc_mask = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(Some("proc"), "/proc", Some("proc"), proc_mask, None as Option<&str>)
        .context("Failed to mount /proc. If you are running within docker/kubernetes, \
                 it's because /proc is protected with read-only mounts. \
                 `--container` cannot be used in this case. \
                 Instead, use `fastfreeze install` in your Dockerfile")?;

    Ok(())
}

fn open_container_proc_dir(name: &str) -> Result<Option<fs::File>> {
    let inner = || -> Result<fs::File> {
        let pid_file_path = CONTAINERS_DIR.join(name).join("run/pid");
        let pid = fs::read_to_string(&pid_file_path)
            .with_context(|| format!("Failed to read {}", pid_file_path.display()))?;
        let pid = pid.trim().parse::<u32>()
            .with_context(|| format!("Failed to parse {}", pid_file_path.display()))?;
        let proc_path = format!("/proc/{}", pid);
        let proc_file = fs::File::open(&proc_path)
            .with_context(|| format!("Failed to open {}", proc_path))?;
        Ok(proc_file)
    };

    match inner() {
        Err(e) if e.downcast_ref::<std::io::Error>().map(|e| e.kind()) == Some(ErrorKind::NotFound) => Ok(None),
        Err(e) => Err(e),
        Ok(f) => Ok(Some(f)),
    }
}

pub fn get_running_containers() -> Result<Vec<String>> {
    // CONTAINERS_DIR may not exist, so we'll get NotFound errors. The code is a
    // little ugly because read_dir() can return errors, and entries too.
    fs::read_dir(&*CONTAINERS_DIR)
        .and_then(|entries| entries
            .map(|name| name
                .map(|n| n.file_name().to_string_lossy().into_owned())
            ).collect()
        ).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(vec![]) } else { Err(e) })
        .with_context(|| format!("Failed to readdir {}", CONTAINERS_DIR.display()))
}

/// When /proc/sys is mounted read-only (or any other subpath of /proc), we won't
/// be able to re-mount /proc. Attempting to create a container is futile in this case.
pub fn can_create() -> Result<bool> {
    let content = fs::read_to_string("/proc/self/mounts")
        .context("Failed to read /proc/self/mounts")?;

    // if we find a line like this: "proc /proc/sys proc ro,relatime 0 0", it's game over.
    for line in content.lines() {
        let line_elems = line.split_whitespace().collect::<Vec<_>>();
        if let &[_dev, path, _fstype, opts, ..] = line_elems.as_slice() {
            if path.starts_with("/proc/sys") && opts.split(",").find(|&x| x == "ro").is_some() {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

pub fn create(name: &str) -> Result<()> {
    // First we check if the container is already running
    if let Some(_) = open_container_proc_dir(name)? {
        bail!("Error: The application `{}` is already running.\n\
               Use `--app-name <name>` with a different name", name);
    }

    info!("Creating container `{}`", name);

    prepare_user_namespace()?;
    prepare_fs_namespace(name)?;
    prepare_pty_namespace()?;

    // The following forks and we become the init process of the container. We
    // prefer doing this compared to having the application being the init
    // process for the container because it matches the same hierachy that we
    // would have if we relied on kubernetes for creating our container.
    // fastfreeze is pid=1 in both cases.
    prepare_pid_namespace()?;

    Ok(())
}

pub fn nsenter(name: &str) -> Result<()> {
    let container_proc_dir = open_container_proc_dir(name)?
        .ok_or_else(|| anyhow!("Error: The application `{}` is not running", name))?;

    let namespaces = [
        ("ns/user", CloneFlags::CLONE_NEWUSER),
        ("ns/mnt",  CloneFlags::CLONE_NEWNS),
        ("ns/pid",  CloneFlags::CLONE_NEWPID)
    ];

    for (path, clone_flag) in &namespaces {
        let nsfile = openat(&container_proc_dir, path)
            .with_context(|| format!("Failed to open container proc file {}", path))?;
        setns(&nsfile, *clone_flag)?;
    }

    if let ForkResult::Parent { child: pid } = fork()? {
        monitor_container(pid);
        unreachable!();
    }

    Ok(())
}

/// Enter the application container when the user provides us with its app name.
/// If no container name is provided, we enter the container that we see running.
/// If we see no containers, we'll see if an application is running outside of a
/// container which is the docker/kubernetes usecase.
pub fn enter_app_namespace(app_name: Option<&String>) -> Result<()> {
    if let Some(ref app_name) = app_name {
        nsenter(app_name)
    } else {
        let containers = get_running_containers()?;
        match containers.len() {
            0 => {
                if install::is_ff_installed()? && is_app_running() {
                    Ok(())
                } else {
                    bail!("Error: No application is running");
                }
            },
            1 => nsenter(&containers[0]),
            _ => {
                let names = containers.iter()
                    .map(|c| format!("* {}", c))
                    .collect::<Vec<_>>()
                    .join("\n");
                bail!("Multiple applications are running, so you must pick one.\n\
                       Re-run the same command with one of the following added at the end\n{}",
                       names);
            },
        }
    }
}
