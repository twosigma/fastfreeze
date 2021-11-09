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
use std::{
    collections::{HashSet, HashMap},
    os::unix::io::RawFd,
    sync::atomic::Ordering,
};
use serde::{Serialize, Deserialize};
use crate::{
    consts::*,
    process::Command,
    util::{get_inheritable_fds, readlink_fd, is_term},
};

// Say the application was originally run with "fastfreeze run app | cat".
// It started with a pipe as stdout. The application may have had duped its fds over its lifetime.
// When we restore, with the same command, we want to replace the occurances of the old
// pipe with the new one. To do so, we need to remember the original pipe inode
// and replace all occurrences of it with the new stdout that we are running
// with. That's where the CRIU --inherit-fd option helps us with. It replaces
// all occurrences of a given resource with a specific fd.
// The `InheritableResources` struct helps us with doing all this.
#[derive(Serialize, Deserialize)]
pub struct InheritableResources(pub HashMap<String, Vec<RawFd>>);
impl InheritableResources {
    /// Returns the list of inheritable resources. These are resources that the application
    /// gains access to, for example a stdout connected to a pipe that has been created outside
    /// of the app container. Regular files don't count as they are accessible from
    /// the application container, and do not need special handling.
    /// Each resource comes with a list of associated file descriptors.
    pub fn current() -> Result<Self> {
        let mut resources: HashMap<String, Vec<RawFd>> = HashMap::new();
        for fd in get_inheritable_fds()? {
            let res_name = readlink_fd(fd)?.to_string_lossy().into_owned();
            if let Some(fds) = resources.get_mut(&res_name) {
                fds.push(fd);
            } else {
                resources.insert(res_name, vec![fd]);
            }
        }

        // CRIU refers to terminal as tty:[rdev:dev], not /dev/pts/0, so we'll
        // rename the resource name in this case.
        let resources: HashMap<String, Vec<RawFd>> = resources.into_iter()
            .map(|(res_name, fds)|
                if is_term(fds[0]) {
                    // expect() here is okay. If fstat() fails, something terrible must have happened.
                    let stat = nix::sys::stat::fstat(fds[0]).expect("fstat failed");
                    (format!("tty[{:x}:{:x}]", stat.st_rdev, stat.st_dev), fds)
                } else {
                    (res_name, fds)
                }
            ).collect();

        for (res_name, fds) in resources.iter() {
            debug!("Application inherits {} via fd:{:?}", res_name, fds);
        }

        Ok(Self(resources))
    }

    pub fn compatible_with(&self, other: &Self) -> bool {
        let a_fds: HashSet<_> = self.0.values().collect();
        let b_fds: HashSet<_> = other.0.values().collect();
        a_fds == b_fds
    }

    pub fn add_remaps_criu_opts(&self, criu_cmd: &mut Command) {
        for (res_name, fds) in &self.0 {
            // We have a resource that can be opened via multiple fds.
            // It doesn't matter which one we take. CRIU reopens the fd
            // correctly anyways through /proc/self/fd/N.
            let mut fd = fds.iter().cloned().next().expect("missing resource fd");

            if fd == libc::STDERR_FILENO {
                // Here's a bit of a problem. CRIU is getting a redirected pipe
                // for stderr so we can buffer its output in run.rs via
                // enable_stderr_logging. That means that we can't export the
                // original stderr on fd=2. We are going to use another one.
                //
                // TODO close that file descriptor once we have forked the CRIU
                // command.
                fd = nix::unistd::dup(fd).expect("dup() failed");
            }

            criu_cmd
                .arg("--inherit-fd")
                .arg(format!("fd[{}]:{}", fd, res_name));
        }
    }

}

// CRIU is running under our CPUID virtualization.
// The CPUID that it detects is virtualized.

pub fn criu_dump_cmd(skip_timens: bool) -> Command {
    let mut cmd = Command::new(&[
        "criu", "dump",
        "--tree", &APP_ROOT_PID.to_string(),
        "--leave-stopped", // Leave app stopped: we resume app once the filesystem is tarred.
        // The rest are some networking options. In a nutshell, we want all
        // external connections to be closed on restore.
        "--empty-ns", "net", "--tcp-established", "--skip-in-flight", "--tcp-close", "--ext-unix-sk"
    ]);

    add_common_criu_opts(&mut cmd, skip_timens);

    cmd
}

pub fn criu_restore_cmd(
    leave_stopped: bool,
    skip_timens: bool,
    previously_inherited_resources: &InheritableResources,
) -> Command {
    let mut cmd = Command::new(&[
        "criu", "restore",
        "--restore-sibling", "--restore-detached", // Become parent of the app (CLONE_PARENT)
        // The rest are some networking options. In a nutshell, we want all
        // external connections to be closed on restore.
        "--tcp-close", "--ext-unix-sk",
    ]);

    if leave_stopped {
        cmd.arg("--leave-stopped");
    }

    add_common_criu_opts(&mut cmd, skip_timens);

    previously_inherited_resources
        .add_remaps_criu_opts(&mut cmd);

    cmd
}

fn add_common_criu_opts(cmd: &mut Command, skip_timens: bool) {
    cmd.arg("--images-dir").arg(&*CRIU_SOCKET_DIR);
    cmd.args(&[
        "--cpu-cap",    // Save and check CPUID information in the image
        "--shell-job",  // Support attached TTYs
        "--file-locks", // Support file locks
        // CRIU has an experimental feature for checking file integrity.
        // It can read the build-id in ELF headers during dump, and compare it during restore.
        // Currently, it emits warnings during dump. So we'll skip it for now.
        "--file-validation", "filesize",
        "--stream",     // Use criu-image-streamer
    ]);

    if skip_timens {
        cmd.arg("--skip-timens");
    }

    // VERBOSITY=2 is when we run FastFreeze in log level = trace. Anything on top
    // of that increases CRIU's verbosity.
    let criu_verbosity = LOG_VERBOSITY.load(Ordering::Relaxed).saturating_sub(2);
    if criu_verbosity > 0 {
        cmd.arg(format!("-{}", "v".repeat(criu_verbosity as usize)));
        cmd.arg("--display-stats");
    }

    let extra_opts = std::env::var_os("CRIU_OPTS").unwrap_or_default();
    cmd.args(extra_opts.to_str()
        .expect("CRIU_OPTS is UTF8 malformed")
        .split_whitespace());
}

pub fn criu_check_cmd() -> Command {
    Command::new(&["criu", "check"])
}
