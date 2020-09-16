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

use crate::{
    consts::*,
    process::Command,
};

// CRIU is running under our CPUID virtualization.
// The CPUID that it detects is virtualized.

pub fn criu_dump_cmd() -> Command {
    let mut cmd = Command::new(&[
        "criu", "dump",
        "--tree", &APP_ROOT_PID.to_string(),
        "--leave-stopped", // Leave app stopped: we resume app once the filesystem is tarred.
        // The rest are some networking options. In a nutshell, we want all
        // external connections to be closed on restore.
        "--empty-ns", "net", "--tcp-established", "--skip-in-flight", "--tcp-close", "--ext-unix-sk"
    ]);

    add_common_criu_opts(&mut cmd);

    cmd
}

pub fn criu_restore_cmd(leave_stopped: bool) -> Command {
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

    add_common_criu_opts(&mut cmd);

    cmd
}

fn add_common_criu_opts(cmd: &mut Command) {
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

    if log_enabled!(log::Level::Trace) {
        cmd.arg("-v"); // verbose
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
