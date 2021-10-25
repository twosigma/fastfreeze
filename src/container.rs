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
    fs,
    path::PathBuf,
    io::ErrorKind,
    path::Path,
    os::unix::io::{RawFd},
    collections::HashSet,
    io::prelude::*,
    thread::sleep,
    time::Duration,
};
use nix::{
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
    sys::signal::{self, kill},
    sys::wait::{waitpid, WaitStatus},
    sys::stat::Mode,
    unistd::{
        fork, ForkResult, Pid,
        getuid, getgid, Uid, Gid,
        lseek64, Whence, dup2, close,
    },
    errno::Errno,
    fcntl::{fcntl, FcntlArg, open, OFlag},
};

use caps::{Capability, CapSet};
use crate::{
    consts::*,
    cli::{ExitCode, install, run::is_app_running},
    process::{monitor_child, ChildDied, Command},
    util::{
        create_dir_all, set_tmp_like_permissions, openat,
        setns, readlink_fd, readlinkat, get_inheritable_fds, is_term
    },
    logger,
    shared_mem::SharedMem,
    virt,
};

pub const CLONE_NEWTIME: CloneFlags = unsafe { CloneFlags::from_bits_unchecked(0x80) };

/// FastFreeze requires the following to run applications:
/// 1) Hijack the ELF system loader (/lib/ld-linux.so). This is important to achieve the following:
///    a) Virtualize CPUID, which needs to happen before libc's ELF loader run.
///    b) Force time user-space virtualization to all processes by LD_PRELOADing libvirttime.
///       Even if a program clears the environment, our hijacking loader will set LD_PRELOAD before
///       any program gets to initialize.
///
/// 2) Control PIDs of processes. During restore, we need to have the same PIDs as
///    during checkpointing.
///
/// 3) Optionally, virtualize /dev/pts/N to avoid conflits.
///
/// 4) Optionally, gain CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE) so that we can
///    restore the /proc/self/exe link.
///
/// We need a few namespaces to accomplish all this.
/// a) First, we need a user namespace to be able to create other namespaces. This also
///    gives us 4).
/// b) Then we need a mount namespace,  to do 1) and 3).
/// c) Then we need a PID namespace to do 3).
///
/// We distinguish 3 cases of operations:
/// * NSCapabilities::Full: We have access to all namespaces. Great.
/// * NSCapabilities::MountOnly: We don't have access to PID namespaces because /proc has
///   subdirectories that are read-only mounted preventing a remount of /proc. This
///   is typical within a Kubernetes environment.
/// * NSCapabilities::None: We can't create any sort of namespaces. That's typical when running
///   within Docker. In this case, our ELF loader must be installed manually, as root.
///   This is done with `fastfreeze install`.
///   Note that we don't want to set any of executables setuid. It makes them secure,
///   which creates all sorts of problems, such as LD_LIBRARY_PATH not being honored.
///
/// Note that only with NSCapabilities::Full can we run multiple applications at
/// the same time (their PIDs will collide otherwise). This is why only in that case we
/// mount bind /var/tmp/fastfreeze to /tmp/fastfreeze/app_name.
///
/// The way the functionality of this file is the following:
/// cli/run.rs calls ns_capabilities() to figure out what namespace we have available. It then
/// figures out what to do.
/// Under NSCapabilities::Full:
/// - `create(app_name)` is called to create the namespaces.
/// - `nsenter(app_name)` is called to enter the namespaces (used during checkpointing).
/// Under NSCapabilities::MountOnly:
/// - `create_without_pid_ns()` is called to create the user and mount namespace.
/// - `nsenter_without_pid_ns()` is called to enter the namespaces.
/// The `nsenter*()` functions are called from the same entry point, `maybe_nsenter_app()`

// Privileges
//////////////////////////////////

#[derive(Default, Clone, Copy, Debug)]
pub struct Privileges {
    // Creating a username space is helpful for elevating capabilities in the
    // local user namespace, and creating time/mount/pid namespaces.
    pub has_user_namespace: bool,

    // Having CAP_SYS_ADMIN is helpful to restore the /proc/PID/exe symlink
    pub has_local_cap_sys_admin: bool,

    // Creating a time namespace is the best way to virtualize the monotonic clock.
    // If we can't, we must fall back using libvirttime.so.
    // Time namespaces are only available on 5.6+ kernels. As of Sep 2021, such
    // kernels are not available on GKE on the stable release:
    // https://cloud.google.com/container-optimized-os/docs/release-notes
    pub has_time_namespace: bool,

    // The mount namespace is important for remounting /proc and doing mount binds.
    pub has_mount_namespace: bool,

    // This is important for and for running multiple application at the same
    // time (each app see their own /var/tmp/fastfreeze, which we prefer the path
    // not to change as it makes the restoring easier as we won't need to remap file
    // paths). Additionally, we can override the ELF loader allowing CPUID
    // virtualization and userspace time virtualization.
    pub can_mount_bind: bool,

    // This is helpful to virtualize the terminal (/dev/pts/0), but not terribly
    // important. Just a nice to have.
    pub can_mount_devpts: bool,

    // The following is for PID control which is important for restoring
    // processes with the same PID as when checkpointed.
    pub has_pid_namespace: bool,
    pub can_mount_proc: bool,
    pub mount_proc_fails_due_to_read_only_protection: bool,
    pub can_write_to_proc_ns_last_pid: bool,
    pub ff_fake_root_fixes_ns_last_pid: bool,

    // If we can't ptrace, we won't be able to checkpoint.
    // Note that we don't like the CRIU executable to be setuid because that
    // creates all sorts of other problems as it turns it into a secure binary
    // and things like LD_PRELOAD don't work.
    pub can_ptrace_siblings: bool,

    // What this really means is whether the ELF loader is hijacked.
    // It's not really a privilege, but it's useful in the context of knowing
    // what facilities we have access to.
    pub ff_installed: bool,
}

impl Privileges {
    pub fn detect() -> Result<Self> {
        fn spawn_child_process(child_fn: impl FnOnce()) -> Result<()> {
            match fork()? {
                ForkResult::Child => {
                    child_fn();
                    std::process::exit(0);
                }
                ForkResult::Parent { child } => {
                    let result = waitpid(child, None)?;
                    match result {
                        WaitStatus::Exited(_, 0) => Ok(()),
                        _ => bail!("Privilege detection failed"),
                    }
                }
            }
        }

        fn raise_capability(cap: caps::Capability) -> Result<()> {
            caps::raise(None, CapSet::Inheritable, cap)?;
            caps::raise(None, CapSet::Ambient, cap)?;
            Ok(())
        }

        let mut p = SharedMem::new(Self::default());

        spawn_child_process(|| {
            p.has_user_namespace = unshare(CloneFlags::CLONE_NEWUSER).is_ok();

            if !p.has_user_namespace {
                // Docker blocks the the use of namespaces with seccomp by default.
                // Not much we can do without a user namespace, let's leave it here.
                return;
            }

            p.has_local_cap_sys_admin = raise_capability(Capability::CAP_SYS_ADMIN).is_ok();

            p.has_time_namespace = unshare(CLONE_NEWTIME).is_ok() &&
                fs::write("/proc/self/timens_offsets", "monotonic 1 0").is_ok();

            p.has_mount_namespace = unshare(CloneFlags::CLONE_NEWNS).is_ok();

            if p.has_mount_namespace {
                p.can_mount_bind = mount_bind("/var/tmp", "/var/tmp").is_ok();
                p.can_mount_devpts = mount(
                    Some("devpts"), "/dev/pts", Some("devpts"),
                    MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    Some("newinstance,ptmxmode=0666")
                ).is_ok();
            }

            p.has_pid_namespace = unshare(CloneFlags::CLONE_NEWPID).is_ok();
            if p.has_pid_namespace && p.has_mount_namespace {
                // We need to fork to enter the PID namespace. Let's see if we can mount /proc
                spawn_child_process(|| {
                    p.can_mount_proc = mount(
                        Some("proc"), "/proc", Some("proc"),
                        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                        Option::<&str>::None
                    ).is_ok();
                    // p.mount_proc_fails_due_to_read_only_protection is populated later

                    if p.can_mount_proc {
                        let ns_last_pid_file = fs::OpenOptions::new().write(true)
                            .open("/proc/sys/kernel/ns_last_pid");
                        p.ff_fake_root_fixes_ns_last_pid = matches!(
                            ns_last_pid_file, Err(ref e) if e.raw_os_error() == Some(libc::EACCES));

                        p.can_write_to_proc_ns_last_pid = ns_last_pid_file
                            .map(|mut f| f.write_all(b"1")).is_ok();
                    }
                }).unwrap(); // We panic if the child fail. The parent will catch the error.
            }
        })?;

        // We detect if proc mounting failures are due to read-only for better error messages.
        if p.has_pid_namespace && p.has_mount_namespace && !p.can_mount_proc {
            let content = fs::read_to_string("/proc/self/mounts")
                .context("Failed to read /proc/self/mounts")?;

            // if we find a line like this: "proc /proc/sys proc ro,relatime 0 0", it's game over.
            for line in content.lines() {
                let line_elems = line.split_whitespace().collect::<Vec<_>>();
                if let [_dev, path, _fstype, opts, ..] = *line_elems {
                    if path.starts_with("/proc/") && opts.split(',').any(|x| x == "ro") {
                        p.mount_proc_fails_due_to_read_only_protection = true;
                        break;
                    }
                }
            }
        }

        // This tests if a process can ptrace a sibling process
        spawn_child_process(|| {
            // We'll try our best to raise CAP_SYS_PTRACE to make ptrace work.
            let _ = unshare(CloneFlags::CLONE_NEWUSER);
            let _ = raise_capability(Capability::CAP_SYS_PTRACE);

            // We fork one process
            let ptraced_child = match fork().expect("fork() failed") {
                ForkResult::Child => {
                    // let the first child block for a while
                    sleep(Duration::from_secs(u64::MAX));
                    unreachable!();
                }
                ForkResult::Parent { child } => child,
            };

            // Then another one, which is now a sibling of the first one.
            // This is similar to how CRIU is attaches to the application.
            let tracer_child = spawn_child_process(|| {
                p.can_ptrace_siblings = nix::sys::ptrace::attach(ptraced_child).is_ok();
            });

            kill(ptraced_child, signal::SIGKILL).expect("kill failed");
            waitpid(ptraced_child, None).expect("waitpid failed");
            tracer_child.expect("tracer process failed");
        })?;

        p.ff_installed = install::is_ff_installed()?;

        Ok(*p)
    }

    pub fn ensure_sufficient_privileges(&self) -> Result<()> {
        // Check that we can enable virtualization immediately
        virt::get_required_virtualization(self)?;

        ensure!(self.can_ptrace_siblings,
            "Cannot ptrace siblings processes. CRIU won't be able to checkpoint the application. \
             Use 'echo 0 > /proc/sys/kernel/yama/ptrace_scope', or allow user namspaces");

        if !self.can_write_to_proc_ns_last_pid {
            if self.ff_fake_root_fixes_ns_last_pid {
                info!("/proc/sys/kernel/ns_last_pid is not writable, which can slow down restores. \
                       This can typically be fixed by upgrading your kernel. \
                       Another solution is to remap your uid to uid=0 in the container, which you can do \
                       by running fastfreeze with FF_FAKE_ROOT=1");
            } else {
                debug!("/proc/sys/kernel/ns_last_pid is not writable, controlling PIDs may be slow");
            }
        }

        if !self.has_local_cap_sys_admin {
            warn!("WARN: The /proc/<PID>/exe symlink won't be restored");
        }

        Ok(())
    }

    /// To run multiple apps, we need to 1) be able to mount bind the per-application
    /// FF directory (/tmp/fastfreeze/<app_name>) and 2) create PID namespaces.
    /// This function returns Ok(()) if we have both, or an error explaining what's missing.
    pub fn ensure_mutiple_apps_support(&self) -> Result<()> {
        ensure!(self.has_user_namespace, "user namespaces are not available");
        ensure!(self.has_pid_namespace, "PID namespaces are not available");
        ensure!(self.has_mount_namespace, "mount namespaces are not available");
        ensure!(self.can_mount_bind, "`mount --bind` fails within a mount namespace");

        ensure!(!self.mount_proc_fails_due_to_read_only_protection,
            "/proc cannot be remounted because some /proc sub-directories are mounted read-only");
        ensure!(self.can_mount_proc, "/proc cannot be remounted");
        Ok(())
    }

    pub fn use_mount_namespace(&self) -> bool {
        // These are only set when self.has_mount_namespace is true
        self.can_mount_bind || self.can_mount_devpts || self.can_mount_proc
    }

    pub fn use_pid_namespace(&self) -> bool {
        self.has_pid_namespace && self.can_mount_proc
    }
}

// User namespace
//////////////////////////////////

fn raise_all_effective_caps_to_ambient() -> Result<()> {
    // We raise all namespace capabilities to ambient to avoid permission issues.
    // We need CAP_SYS_ADMIN (or CAP_CHECKPOINT_RESTORE), at the very least.
    // for writing to /proc/sys/kernel/ns_last_pid.

    for cap in caps::read(None, CapSet::Effective)? {
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
    trace!("Preparing user namespace");

    let uid = getuid();
    let gid = getgid();

    unshare(CloneFlags::CLONE_NEWUSER)
        .context("Failed to create user namespace")?;

    raise_all_effective_caps_to_ambient()?;

    // We preserve our uid/gid to make things as transparent as possible for the user.
    // However, it doesn't always work on old kernels. So FF_FAKE_ROOT will drop uid to 0.
    let (new_uid, new_gid) = if std::env::var_os("FF_FAKE_ROOT").map_or(false, |v| v == "1") {
        debug!("Using uid=0 in the user namespace (FF_FAKE_ROOT)");
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


// Mount namespace + FF_DIR setup
//////////////////////////////////

pub fn mount_bind(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let from = from.as_ref();
    let to = to.as_ref();
    // It seems that we don't need to mount with MS_PRIVATE.
    mount(Some(from), to, None as Option<&str>, MsFlags::MS_BIND, None as Option<&str>)
        .with_context(|| format!("Failed to bind mount {} to {}", from.display(), to.display()))
}

pub fn prepare_fs_namespace(p: &Privileges, container_name: Option<&str>) -> Result<()> {
    // Note: When this function fails, there's no undo for has already been done. That's fine
    trace!("Preparing FS namespace");

    if p.use_mount_namespace() {
        unshare(CloneFlags::CLONE_NEWNS)
            .context("Failed to create mount namespace")?;
    }

    // Note that we already have the FF_DIR created by the logger, but we'll
    // create the directory again anyways as a precaution.
    create_dir_all(&*FF_DIR)?;

    if let Some(container_name) = container_name {
        let private_ff_dir = CONTAINERS_DIR.join(container_name);

        // `rm -rf` and `mkdir -p` to get a clean working directory
        let _ = fs::remove_dir_all(&private_ff_dir);
        create_dir_all(&private_ff_dir)?;

        // We set /tmp-like permissions on CONTAINER_DIR to allow other users to create
        // their own private ff_dirs. It's okay if it fails
        let _ = set_tmp_like_permissions(&*CONTAINERS_DIR);

        // We relocate the log file from FF_DIR to the container's log file
        // directory. This is helpful to preserve log files in checkpointed images.
        logger::move_log_file(&private_ff_dir.join("logs"))?;

        // if we are given a container name, that means that p.ensure_mutiple_apps_support()
        // returned Ok(()), so we should be able to mount bind.
        mount_bind(&private_ff_dir, &*FF_DIR)?;

        install::prepare_ff_dir()?;
    } else if !p.ff_installed {
        install::prepare_ff_dir()
            .context("Failed to prepare FastFreeze directory. Try `fastfreeze install` first")?;
    }

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

// Takes a slice of TTY fds, and return the path (/dev/pts/X) of the TTY.
// Note that we take an array of TTY fds to ensure that they all point to the
// same TTY, but semantically, we would be taking just a single fd.
fn get_tty_path(tty_fds: &[RawFd]) -> Result<Option<PathBuf>> {
    if tty_fds.is_empty() {
        return Ok(None);
    }

    let paths = tty_fds.iter()
        .copied()
        .map(readlink_fd)
        .collect::<Result<HashSet<_>>>()?;

    assert!(!paths.is_empty());
    ensure!(paths.len() == 1, "Multiple TTYs detected ({:?}), this is not supported", paths);
    Ok(paths.into_iter().next())
}

fn prepare_pty_namespace(inheritable_tty_path: Option<&PathBuf>) -> Result<()> {
    // PTYs can be created by the application (by a program like tmux or sshd).
    // They need to be conflict free when restoring (/dev/pts/N should be available),
    // so we need some amount of virtualization.
    // We want to mount our new namespace on /dev/pts, but we want to map our
    // current pty to /dev/pts/0. We'll do some trickeries with mount binds to
    // achieve that.

    trace!("Preparing PTY namespace");

    // Step 1: Make a bind backup of our /dev/pts/N to CONTAINER_PTY because we are
    // about to hide it with the next mount.
    if let Some(ref tty_path) = inheritable_tty_path {
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
            Some("newinstance,ptmxmode=0666"))
        .context("Failed to mount /dev/pts")?;
    mount_bind("/dev/pts/ptmx", "/dev/ptmx")?;

    // Step 3: mount bind CONTAINER_PTY to /dev/pts/0.
    // For this to work, /dev/pts/0 must exist. So we create a dummy pts
    // that we keep open to ensure that the mount bind survives.
    // We leak the fd on purpose so it doesn't get closed.
    if inheritable_tty_path.is_some() {
        let ptmx_fd = fs::OpenOptions::new()
            .read(true).write(true)
            .open("/dev/ptmx")
            .context("Failed to open /dev/ptmx to create a dummy PTY")?;
        std::mem::forget(ptmx_fd);

        mount_bind(&*CONTAINER_PTY, "/dev/pts/0")?;
    }

    Ok(())
}

fn reopen_fds(fds: &[RawFd], remapped_tty_fds: &[RawFd]) -> Result<()> {
    // Eearlier, we created a new mount namespace, and that changes all the
    // mount ids seen in /proc/PID/mountinfo. We need to re-open the fds that
    // we'll pass to the application. Otherwise, the mnt_id of
    // /proc/PID/fdinfo/<fd> will not match a visible mount id when invoking CRIU.
    // On top of that, we have the tty to reopen on /dev/pts/0 when using devpts
    // virtualization.

    fn reopen_fd(fd: RawFd, path: &Path) -> Result<()> {
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let flags = unsafe { OFlag::from_bits_unchecked(flags) };

        let pos = match lseek64(fd, 0, Whence::SeekCur) {
            Ok(pos) => Some(pos),
            Err(e) if e.as_errno() == Some(Errno::ESPIPE) => None,
            Err(e) => Err(e).context("lseek() failed")?,
        };
        let new_fd = open(path, flags, Mode::empty()).context("open() failed")?;
        if let Some(pos) = pos {
            lseek64(new_fd, pos, Whence::SeekSet).context("lseek() failed")?;
        }

        dup2(new_fd, fd).context("dup2() failed")?;
        close(new_fd).context("close() failed")?;

        Ok(())
    }

    for &fd in fds {
        let path = if remapped_tty_fds.contains(&fd) {
            PathBuf::from("/dev/pts/0")
        } else {
            readlink_fd(fd)?
        };

        // Re-open files that are accessible from the file system.
        if path.starts_with("/") {
            debug!("Reopening fd={} path={}", fd, path.display());
            reopen_fd(fd, &path)
                .with_context(|| format!("Failed to re-open {}", path.display()))?;
        }
    }

    Ok(())
}

// PID namespace
//////////////////////////////////

fn container_monitor_exit_process(monitor_child_result: Result<()>) -> ! {
    if let Err(e) = monitor_child_result {
        // Our child logs errors when exiting, so we skip logging in this case
        match e.downcast_ref::<ChildDied>() {
            Some(ChildDied::Exited(_)) => {},
            Some(ChildDied::Signaled(s)) => log::error!("ERROR: Container monitor caught fatal signal {}", s),
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
    trace!("Preparing PID namespace");

    unshare(CloneFlags::CLONE_NEWPID)
        .context("Failed to create PID namespace")?;

    if let ForkResult::Parent { child: container_pid } = fork()? {
        // We write down the container init process pid. It will be useful later
        // to entering the container when checkpointing (or with nsenter).
        // If we fail, we kill the container immediately.
        write_container_pid_file(container_pid)
            .map_err(|e| { let _ = kill(container_pid, signal::SIGKILL); e })?;

        let result = monitor_child(container_pid, true);
        cleanup_current_container();
        container_monitor_exit_process(result);
        // unreachable
    }

    // We are now in the new PID namespace, as the init process

    // We can mount /proc because we have a root-mapped user namespace :)
    // This won't work if we are in a docker/kubernetes environment with a
    // protected /proc with a bunch of read-only subdirectory binds.
    let proc_mask = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mount(Some("proc"), "/proc", Some("proc"), proc_mask, None as Option<&str>)
        .context("Failed to mount /proc")?;

    Ok(())
}

/// Returns the tuple (proc_dir, pid) if the application is running
fn open_container_proc_dir(name: &str) -> Result<Option<(fs::File, u32)>> {
    let inner = || -> Result<(fs::File, u32)> {
        let pid_file_path = CONTAINERS_DIR.join(name).join("run/pid");
        let pid = fs::read_to_string(&pid_file_path)
            .with_context(|| format!("Failed to read {}", pid_file_path.display()))?;
        let pid = pid.trim().parse::<u32>()
            .with_context(|| format!("Failed to parse {}", pid_file_path.display()))?;
        let proc_path = format!("/proc/{}", pid);
        let proc_file = fs::File::open(&proc_path)
            .with_context(|| format!("Failed to open {}", proc_path))?;
        Ok((proc_file, pid))
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


// create + enter containers
////////////////////////////////

pub fn create(p: &Privileges, container_name: Option<&str>) -> Result<()> {
    if let Some(name) = container_name {
        ensure!(!name.is_empty(), "Application name is empty");

        if let Some((_, pid)) = open_container_proc_dir(name)? {
            bail!("Error: The application `{}` is already running (pid={}).\n\
                   Use `--app-name <name>` to specify a different name", name, pid);
        }
        info!("Preparing container `{}`", name);
    } else {
        info!("Preparing environment for app");
    }

    // We always use a user namespace if we can, it ensures that we have local
    // CAP_SYS_ADMIN privileges to set the /proc/PID/exe symlink, and it gives
    // us better ptrace privileges as well (so we don't have to worry about the
    // default yama ptrace_scope=1 protection).
    if p.has_user_namespace {
        prepare_user_namespace()
            .context("Failed to prepare user namespace")?;
    }

    // Create a mount namespace and setup our FF_DIR.
    prepare_fs_namespace(p, container_name)
        .context("Failed to prepare FS namespace")?;

    let fds = get_inheritable_fds()?;
    if p.can_mount_devpts {
        let tty_fds: Vec<_> = fds.iter().cloned().filter(|fd| is_term(*fd)).collect();
        let tty_path = get_tty_path(&tty_fds)?;
        prepare_pty_namespace(tty_path.as_ref())
            .context("Failed to prepare devpts")?;
        reopen_fds(&fds, &tty_fds)?;
    } else {
        // we must reopen the fds the app will inherit, even if we don't use
        // mount namespaces, because we can be in mount namespace without
        // knowing it.
        reopen_fds(&fds, &[])?;
    }

    // The following forks. The current process becomes the init process of the
    // container, and the child is the one continuing the execution of fastfreeze.
    // We prefer doing this compared to having the application being the init
    // process for the container because it matches the same hierachy that we
    // would have if we relied on kubernetes for creating our container.
    // fastfreeze is pid=1 in both cases.
    if p.use_pid_namespace() {
        prepare_pid_namespace()
            .context("Failed to prepare pid namespace")?;
    }

    // The time namespace is created later

    Ok(())
}

fn enter_inner(name: Option<&str>) -> Result<()> {
    let container_proc_dir = if let Some(name) = name {
        ensure!(!name.is_empty(), "Application name is empty");

        let (container_proc_dir, _pid) = open_container_proc_dir(name)?
            .ok_or_else(|| anyhow!("Error: The application `{}` is not running", name))?;

        // We relocate the log file in the container's log file directory.
        // This is helpful to preserve log files in checkpointed images.
        // We need to do this first, because once we enter the mount namespace,
        // we won't see the old log file anymore.
        let private_ff_dir = CONTAINERS_DIR.join(name);
        logger::move_log_file(&private_ff_dir.join("logs"))?;
        container_proc_dir
    } else {
        fs::File::open(format!("/proc/{}", APP_ROOT_PID))
            .context("Failed to open application's /proc directory")?
    };

    let self_proc_dir = fs::File::open("/proc/self")
        .context("Failed to open /proc/self")?;

    // Returns true if we had to enter the application's namespace,
    // false if the application had no distinct namespace (i.e. we share the same namespace)
    let nsenter = |ns_path: &str| -> Result<bool> {
        // comparing the ns symlinks is a way to determine if we are in a different namespace.
        if readlinkat(&self_proc_dir, ns_path)? != readlinkat(&container_proc_dir, ns_path)? {
            trace!("Entering namespace {}", ns_path);
            let nsfile = openat(&container_proc_dir, ns_path)?;
            // CloneFlags::empty means "Allow any type of namespace to be joined."
            setns(&nsfile, CloneFlags::empty())?;
            Ok(true)
        } else {
            Ok(false)
        }
    };

    if nsenter("ns/user")? {
        raise_all_effective_caps_to_ambient()?;
    }
    nsenter("ns/mnt")?;
    if nsenter("ns/pid")? {
        if let ForkResult::Parent { child: pid } = fork()? {
            let result = monitor_child(pid, true);
            container_monitor_exit_process(result);
            // unreachable
        }
    }

    // We don't enter the time namespace. It makes things difficult to reason
    // about. For example, we'd need to adjust the START_TIME variable, and we
    // would need to be careful when doing app clock computation.
    // The best would have been to enter the time namespace as a parent just so
    // our children processes would be affected (e.g., using 'ns/time_for_children'),
    // but that doesn't work.

    Ok(())
}

/// Enter the application container when the user provides us with its app name.
/// If no container name is provided, we enter the container that we see running.
/// If we see no containers, we'll see if an application is running outside of a
/// proper container which is what happens with Docker/Kubernetes.
pub fn enter(container_name: Option<&str>) -> Result<()> {
    if let Some(name) = container_name {
        enter_inner(Some(name))
    } else {
        match get_running_containers()?.as_slice() {
            [] if is_app_running() => enter_inner(None),
            [] => bail!("Error: No application is running"),
            [single_container] => enter_inner(Some(single_container)),
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

pub fn cmd_enter_ns(cmd: &mut Command, ns_path: &str) -> Result<()>
{
    let time_ns_file = fs::File::open(&ns_path)
        .with_context(|| format!("Cannot open {}", &ns_path))?;
    let set_time_ns = move || {
        // Panicking is okay. The stderr is captured in our case.
        setns(&time_ns_file, CloneFlags::empty())
            .expect("setns() failed");
        Ok(())
    };
    unsafe { cmd.pre_exec(set_time_ns); }
    Ok(())
}
