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
    os::unix::io::{RawFd, AsRawFd},
    collections::HashSet,
};
use nix::{
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
    sys::signal::{self, kill},
    sys::termios::tcgetattr,
    sys::wait::{waitpid, WaitStatus},
    sys::stat::Mode,
    unistd::{
        fork, ForkResult, Pid,
        getuid, getgid, Uid, Gid,
        lseek64, Whence, dup2, close,
    },
    fcntl::{fcntl, FcntlArg, open, OFlag},
};

use caps::CapSet;
use crate::{
    consts::*,
    cli::{ExitCode, install, run::is_app_running},
    process::{monitor_child, ChildDied},
    util::{create_dir_all, set_tmp_like_permissions, openat, setns},
    logger,
};

#[derive(PartialEq)]
pub enum NSCapabilities {
    None,
    MountOnly,
    Full,
}

impl NSCapabilities {
    pub fn has_restrictions(&self) -> bool { *self != Self::Full }
    pub fn can_mount_ns(&self) -> bool { *self != Self::None }
}

/// When /proc/sys is mounted read-only (or any other subpath of /proc), we won't
/// be able to re-mount /proc. Attempting to create a container is futile in this case.
pub fn ns_capabilities() -> Result<NSCapabilities> {
    fn test_in_child_process(child_fn: impl FnOnce() -> Result<()>) -> Result<bool> {
        match fork()? {
            ForkResult::Child => {
                let result = child_fn();
                std::process::exit(if result.is_ok() { 0 } else { 1 });
            }
            ForkResult::Parent { child } => {
                let result = waitpid(child, None)?;
                Ok(matches!(result, WaitStatus::Exited(_, 0)))
            },
        }
    };

    let can_create_mount_ns = test_in_child_process(|| -> Result<()> {
        unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)?;
        Ok(())
    })?;

    let can_create_pid_ns = test_in_child_process(|| -> Result<()> {
        // We don't call prepare_pid_namespace() because it does too much
        // The following is sufficient to test what we need
        unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID)?;
        ensure!(test_in_child_process(|| -> Result<()> {
            let proc_mask = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
            mount(Some("proc"), "/proc", Some("proc"), proc_mask, None as Option<&str>)?;
            Ok(())
        })?, "mount proc failed");
        Ok(())
    })?;

    let cap = match (can_create_mount_ns, can_create_pid_ns) {
        // Docker blocks the the use of namespaces with seccomp by default.
        // It's not a big deal. User can run `fastfreeze install` when creating the docker image.
        // run() will emit a proper error message.
        (false, _) => NSCapabilities::None,

        // We could be on Kubernetes, where we have a shadow /proc prevending us to
        // use a PID namespace correctly, but we can do mount namespaces.
        (true, false) => NSCapabilities::MountOnly,

        (true, true) => NSCapabilities::Full,

        // We don't consider the case where we can only create a pid ns, and not
        // a mount ns because it's very unlikely.
    };

    // MountOnly deserves a debug message here as we want to report if /proc is read-only protected.
    if cap == NSCapabilities::MountOnly {
        let is_proc_ro_protected = || -> Result<bool> {
            let content = fs::read_to_string("/proc/self/mounts")
                .context("Failed to read /proc/self/mounts")?;

            // if we find a line like this: "proc /proc/sys proc ro,relatime 0 0", it's game over.
            for line in content.lines() {
                let line_elems = line.split_whitespace().collect::<Vec<_>>();
                if let [_dev, path, _fstype, opts, ..] = *line_elems {
                    if path.starts_with("/proc/sys") && opts.split(',').any(|x| x == "ro") {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        };

        debug!("PID namespaces are not supported{}",
            if is_proc_ro_protected()? { " because /proc is read-only protected" } else { "" });
        debug!("Running multiple applications is not supported, and controlling PIDs may be slow");
    }

    Ok(cap)
}


// User namespace
//////////////////////////////////

fn raise_all_effective_caps_to_ambient() -> Result<()> {
    // We raise all namespace capabilities to ambient to avoid permission issues.
    // We need CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE), at the very least.
    // for writing to /proc/sys/kernel/ns_last_pid.

    for cap in caps::read(None, CapSet::Effective)? {
        trace!("Raising {}", cap);

        caps::raise(None, CapSet::Inheritable, cap)
            .with_context(|| format!("Failed to make {} inheritable", cap))?;

        caps::raise(None, CapSet::Ambient, cap)
            .with_context(|| format!("Failed to make {} ambient", cap))?;
    }

    Ok(())
}

fn prepare_user_namespace() -> Result<()> {
    // The user namespace gives us the ability to mount /proc, mount bind, and
    // control /proc/sys/kernel/ns_last_pid.
    let uid = getuid();
    let gid = getgid();

    unshare(CloneFlags::CLONE_NEWUSER)
        .context("Failed to create user namespace")?;

    raise_all_effective_caps_to_ambient()?;

    // We preserve our uid/gid to make things as transparent as possible for the user.
    // However, it doesn't always work on old kernels. So FF_FAKE_ROOT will drop uid to 0.
    let (new_uid, new_gid) = if std::env::var_os("FF_FAKE_ROOT") == Some("1".into()) {
        (Uid::from_raw(0), Gid::from_raw(0))
    } else {
        (uid, gid)
    };

    fs::write("/proc/self/setgroups", "deny")
        .context("Failed to write to /proc/self/setgroups")?;

    fs::write("/proc/self/uid_map", format!("{} {} 1", new_uid, uid))
        .context("Failed to write to /proc/self/uid_map")?;

    fs::write("/proc/self/gid_map", format!("{} {} 1", new_gid, gid))
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

// We are just hijacking the system ELF loader
fn prepare_fs_namespace_virt_install_only() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS)
        .context("Failed to create mount namespace")?;

    install::prepare_ff_dir()?;
    mount_bind(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH)?;

    Ok(())
}

fn cleanup_current_container() {
    // The container has died. We clean up the container pid file to speed up
    // the enumeration of running containers and also make it more reliable.
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
}

// PTY "namespace"
//////////////////////////////////

/// Returns fds among 0,1,2 that corresponds to a TTY.
pub fn get_tty_fds() -> Vec<RawFd> {
    // We examine stdin/stdout/stderr and select what responds to a TTY.
    [0,1,2].iter()
        .copied()
        .filter(|&fd| tcgetattr(fd).is_ok())
        .collect()
}

fn readlink_fd(fd: RawFd) -> Result<PathBuf> {
    let path = format!("/proc/self/fd/{}", fd);
    fs::read_link(&path)
        .with_context(|| format!("Failed to readlink {}", &path))
}

// Takes an array of TTY fds, and return the path (/dev/pts/X) of the TTY.
// Note that we take an array of TTY fds to ensure that they all point to the
// same TTY, but semantically, we would just be taking just a single fd.
fn get_tty_path(tty_fds: &[RawFd]) -> Result<PathBuf> {
    let paths = tty_fds.iter()
        .copied()
        .map(readlink_fd)
        .collect::<Result<HashSet<_>>>()?;

    assert!(!paths.is_empty());
    ensure!(paths.len() == 1, "Multiple TTYs detected");
    Ok(paths.into_iter().next().unwrap())
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
        debug!("Mapping PTY {} to a new PTY namespace as /dev/pts/0", tty_path.display());
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
    // We leak the fd on purpose so it doesn't get closed.
    if !tty_fds.is_empty() {
        let ptmx_fd = fs::OpenOptions::new().read(true).write(true).open("/dev/ptmx")
            .context("Failed to open /dev/ptmx to create a dummy PTY")?;
        std::mem::forget(ptmx_fd);

        mount_bind(&*CONTAINER_PTY, "/dev/pts/0")?;

        // The application inherits our PTY. The /proc/self/fdinfo/<N>
        // information will show a mount id outside of the mount namespace and that
        // makes CRIU unhappy. We re-open the PTYs bringing them into our own mount
        // namespace.
        let new_pts_0 = fs::OpenOptions::new().read(true).write(true).open("/dev/pts/0")
            .context("Failed to reopen /dev/pts/0")?;

        for &fd in &tty_fds {
            // dup2 does not copy the close-on-exec flag, which is what we want.
            dup2(new_pts_0.as_raw_fd(), fd)
                .context("dup2() failed")?;
        }
    }

    // Step 4: If one of the stdin/stdout/stderr is a regular file, we need to
    // reopen the target to get it into our mount namespace, otherwise it spooks CRIU.
    // Note: at some point, we might want to do this for all fds.
    fn reopen_fd(fd: RawFd, path: &Path) -> Result<()> {
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let flags = unsafe { OFlag::from_bits_unchecked(flags) };

        let pos = lseek64(fd, 0, Whence::SeekCur).context("lseek() failed")?;
        let new_fd = open(path, flags, Mode::empty()).context("open() failed")?;
        lseek64(new_fd, pos, Whence::SeekSet).context("lseek() failed")?;

        dup2(new_fd, fd).context("dup2() failed")?;
        close(new_fd).context("close() failed")?;

        Ok(())
    }

    for &fd in &[0,1,2] {
        if tty_fds.contains(&fd) {
            continue;
        }

        // The target can be a pipe, in which case we don't want to reopen it.
        // We open re-open regular files.
        let path = readlink_fd(fd)?;
        if !path.starts_with("/") {
            continue;
        }

        reopen_fd(fd, &path)
            .with_context(|| format!("Failed to re-open {}", path.display()))?;
    }

    Ok(())
}

// PID namespace
//////////////////////////////////

fn monitor_container(container_pid: Pid) -> ! {
    let result = monitor_child(container_pid);

    cleanup_current_container();

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

fn write_container_pid_file(pid: Pid) -> Result<()> {
    fs::write(&*CONTAINER_PID, format!("{}\n", pid))
        .with_context(|| format!("Failed to write to file {}", CONTAINER_PID.display()))
}

fn prepare_pid_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWPID)
        .context("Failed to create PID namespace")?;

    if let ForkResult::Parent { child: container_pid } = fork()? {
        // We write down the container init process pid. It will be useful later
        // to entering the container when checkpointing (or with nsenter).
        // If we fail, we kill the container immediately.
        write_container_pid_file(container_pid)
            .map_err(|e| { let _ = kill(container_pid, signal::SIGKILL); e })?;

        monitor_container(container_pid);
        // unreachable
    }

    // We are now in the new PID namespace, as the init process

    // We can mount /proc because we have a root-mapped user namespace :)
    // This won't work if we are in a docker/kubernetes environment with a
    // protected /proc with a bunch of read-only subdirectory binds.
    let proc_mask = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(Some("proc"), "/proc", Some("proc"), proc_mask, None as Option<&str>)
        .context("Failed to mount /proc")?;

    if matches!(fs::OpenOptions::new().write(true).open("/proc/sys/kernel/ns_last_pid"),
        Err(e) if e.raw_os_error() == Some(libc::EACCES)) {
            warn!("WARN: /proc/sys/kernel/ns_last_pid is not writable, which can slow down restores. \
                   This can typically be fixed by upgrading your kernel. \
                   Another solution is to remap your uid to uid=0 in the container, which you can do \
                   by running fastfreeze with FF_FAKE_ROOT=1");
    }

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
    // little ugly because read_dir() can return errors, and entries can too.
    let containers = fs::read_dir(&*CONTAINERS_DIR)
        .and_then(|entries| entries
            .map(|name| name
                .map(|n| n.file_name().to_string_lossy().into_owned())
            ).collect()
        ).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(vec![]) } else { Err(e) })
        .with_context(|| format!("Failed to readdir {}", CONTAINERS_DIR.display()))?;

    let mut result = vec![];
    for name in containers {
        if open_container_proc_dir(&name)?.is_some() {
            result.push(name);
        }
    }

    Ok(result)
}

pub fn create(name: &str) -> Result<()> {
    // First we check if the container is already running
    if open_container_proc_dir(name)?.is_some() {
        bail!("Error: The application `{}` is already running.\n\
               Use `--app-name <name>` to specify a different name", name);
    }

    info!("Creating container for app named `{}`", name);

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

pub fn create_virt_install_env() -> Result<()> {
    debug!("Creating a user and mount namespace to virtualize the system ELF loader");

    prepare_user_namespace()?;
    prepare_fs_namespace_virt_install_only()?;
    prepare_pty_namespace()?;

    Ok(())
}

fn nsenter(name: &str) -> Result<()> {
    let container_proc_dir = open_container_proc_dir(name)?
        .ok_or_else(|| anyhow!("Error: The application `{}` is not running", name))?;

    // We relocate the log file in the container's log file directory.
    // This is helpful to preserve log files in checkpointed images.
    // We need to do this first, because once we enter the mount namespace,
    // we won't see the log file anymore.
    let private_ff_dir = CONTAINERS_DIR.join(name);
    logger::move_log_file(&private_ff_dir.join("logs"))?;

    let namespaces = [
        ("ns/user", CloneFlags::CLONE_NEWUSER),
        ("ns/mnt",  CloneFlags::CLONE_NEWNS),
        ("ns/pid",  CloneFlags::CLONE_NEWPID)
    ];

    for (ns_path, clone_flag) in &namespaces {
        let nsfile = openat(&container_proc_dir, ns_path)?;
        setns(&nsfile, *clone_flag)?;
    }

    raise_all_effective_caps_to_ambient()?;

    if let ForkResult::Parent { child: pid } = fork()? {
        monitor_container(pid);
        // unreachable
    }

    Ok(())
}

pub fn maybe_nsenter_virt_install_env() -> Result<()> {
    let current_user_ns = fs::read_link("/proc/self/ns/user")
        .context("Failed to readlink(/proc/self/ns/user)")?;
    let target_user_ns = fs::read_link(format!("/proc/{}/ns/user", APP_ROOT_PID))
        .context("Failed to readlink(/proc/self/ns/user)")?;

    if current_user_ns != target_user_ns {
        let namespaces = [
            ("ns/user", CloneFlags::CLONE_NEWUSER),
            ("ns/mnt",  CloneFlags::CLONE_NEWNS),
        ];

        let container_proc_dir = fs::File::open(format!("/proc/{}", APP_ROOT_PID))?;

        for (ns_path, clone_flag) in &namespaces {
            let nsfile = openat(&container_proc_dir, ns_path)?;
            setns(&nsfile, *clone_flag)?;
        }

        raise_all_effective_caps_to_ambient()?;
    }

    Ok(())
}

/// Enter the application container when the user provides us with its app name.
/// If no container name is provided, we enter the container that we see running.
/// If we see no containers, we'll see if an application is running outside of a
/// container which is what happens with Docker/Kubernetes.
pub fn maybe_nsenter_app(app_name: Option<&String>) -> Result<()> {
    if let Some(ref app_name) = app_name {
        ensure!(!app_name.is_empty(), "app_name is empty");
        nsenter(app_name)
    } else {
        match get_running_containers()?.as_slice() {
            [] if is_app_running() => maybe_nsenter_virt_install_env(),
            [] => bail!("Error: No application is running"),
            [single_container] => nsenter(single_container),
            names => {
                let formatted_names = names.iter()
                    .map(|c| format!("* {}", c))
                    .collect::<Vec<_>>()
                    .join("\n");
                bail!("Multiple applications are running, so you must pick one.\n\
                       Re-run the same command with one of the following appended to the command\n{}",
                       formatted_names);
            },
        }
    }
}
