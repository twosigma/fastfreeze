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
    time::Duration,
    io::Error as IoError,
    fs,
};
use crate::consts::*;
use super::{Command, Process};

// At times, we wish to spawn a process with a desired PID.
// We do so when running the application from scratch.

/// When the child fails, it can only provide an i32 errno to the parent as
/// information with the current pre_exec() from the Rust stdlib.
const BAD_PID_ERRNO: i32 = 0x0BAD_71D0;

/// `MIN_PID` is the pid Linux gives to a process when it wraps around PID_MAX
pub const MIN_PID: i32 = 300;

pub trait CommandPidExt {
    fn spawn_with_pid(self, pid: i32) -> Result<Process>;
}

impl CommandPidExt for Command {
    /// Spawns the command with the desired PID.
    /// Note: we consume self because we mutate it, and it would be unsound to
    /// call `spawn()` again on it.
    fn spawn_with_pid(mut self, pid: i32) -> Result<Process> {
        debug_assert!(pid >= MIN_PID);

        unsafe {
            self.pre_exec(move ||
                if std::process::id() as i32 != pid {
                    Err(IoError::from_raw_os_error(BAD_PID_ERRNO))
                } else {
                    Ok(())
                }
            );
        }

        set_ns_last_pid(pid-1)?;

        self.spawn().map_err(|e| {
            if let Some(e) = e.downcast_ref::<IoError>() {
                if e.raw_os_error() == Some(BAD_PID_ERRNO) {
                    return anyhow!(
                        "Failed to spawn process with pid={}. \
                         This happens when other processes are being spawn simultaneously. \
                         The `--on-app-ready` hook can be useful to run programs once safe to do.", pid);
                }
            }
            e
        })
    }
}

pub fn set_ns_last_pid(pid: i32) -> Result<()> {
    Command::new(&["set_ns_last_pid", &pid.to_string()])
        .spawn()?
        .wait_for_success()
}

pub fn spawn_set_ns_last_pid_server() -> Result<Process> {
    match fs::remove_file(&*NS_LAST_PID_SOCK_PATH) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => bail!(e),
        Ok(_) => {},
    }

    let mut process = Command::new(&["set_ns_last_pid"])
        .arg(&*NS_LAST_PID_SOCK_PATH)
        .spawn()?;

    while !NS_LAST_PID_SOCK_PATH.exists() {
        if process.try_wait()?.is_some() {
            process.wait_for_success()?;
            bail!("set_ns_last_pid exited");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(process)
}
