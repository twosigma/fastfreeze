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
    sync::atomic::{AtomicBool, Ordering},
    error::Error,
    fmt::Display,
    result::Result as StdResult,
    io::{BufReader, ErrorKind},
    fs::File,
    path::Path
};
use std::io::prelude::*;
use std::collections::HashSet;
use nix::{
    sys::signal::{self, killpg, Signal},
    errno::Errno,
    unistd::Pid
};

lazy_static! {
    static ref SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);
}

pub fn trap_sigterm_and_friends() -> Result<()> {
    for signal in &[signal::SIGTERM, signal::SIGHUP, signal::SIGINT] {
        unsafe {
            // We cannot emit a log message in the signal handler as it
            // would be unsafe to allocate memory.
            signal_hook::register(*signal as i32, ||
                SIGTERM_RECEIVED.store(true, Ordering::SeqCst))?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct TerminationRequestedError;
impl Error for TerminationRequestedError {}
impl Display for TerminationRequestedError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Termination requested")
    }
}

/// Returns an error when a SIGTERM has been received. The signal is
/// consumed, meaning that a subsequent call to `check_for_pending_sigterm()`
/// will succeed unless another SIGTERM is received.
pub fn check_for_pending_sigterm() -> Result<()> {
    if SIGTERM_RECEIVED.swap(false, Ordering::SeqCst) {
        info!("Termination requested");
        bail!(TerminationRequestedError);
    }
    Ok(())
}

pub trait IsErrorInterrupt {
    fn is_interrupt(&self) -> bool;
}

impl IsErrorInterrupt for nix::Error {
    fn is_interrupt(&self) -> bool {
        match &self {
            Self::Sys(errno) if *errno == Errno::EINTR => true,
            _ => false
        }
    }
}

impl IsErrorInterrupt for std::io::Error {
    fn is_interrupt(&self) -> bool {
        self.kind() == ErrorKind::Interrupted
    }
}

impl IsErrorInterrupt for anyhow::Error {
    fn is_interrupt(&self) -> bool {
        match self.downcast_ref::<nix::Error>() {
            Some(e) if e.is_interrupt() => return true,
            _ => {}
        }

        match self.downcast_ref::<std::io::Error>() {
            Some(e) if e.is_interrupt() => return true,
            _ => {}
        }

        false
    }
}

pub fn retry_on_interrupt<R,E>(mut f: impl FnMut() -> StdResult<R,E>) -> StdResult<R,E>
    where E: IsErrorInterrupt
{
    loop {
        match f() {
            Err(e) if e.is_interrupt() => {}
            other => return other,
        }
    }
}

fn get_children(pid: i32) -> Result<Vec<i32>> {
    let task_dir = Path::new("/proc").join(pid.to_string()).join("task");
    let mut children_str = String::new();
    // We are okay to fail to open the task directory. That would mean that the
    // task just disappeared.
    if let Ok(task_dir_reader) = task_dir.read_dir() {
        for task_entry in task_dir_reader {
            // The children file ends with a space, and no new line, making it
            // suitable to read repeatedly, and append the content in a single string buffer.
            // Note: We tolerate open failures as the child may disappear.
            if let Ok(mut file) = File::open(task_entry?.path().join("children")) {
                file.read_to_string(&mut children_str)?;
            }
        }
    }

    Ok(children_str.trim().split_whitespace()
        .map(|pid| pid.parse().expect("non-numeric pid"))
        .collect())
}

fn get_process_tree(root_pid: i32) -> Result<Vec<i32>> {
    fn get_process_tree_inner(pid: i32, pids: &mut Vec<i32>) -> Result<()> {
        pids.push(pid);
        for child in get_children(pid)? {
            get_process_tree_inner(child, pids)?;
        }
        Ok(())
    }

    let mut pids = Vec::new();
    get_process_tree_inner(root_pid, &mut pids)?;
    Ok(pids)
}

/// Kill an entire process group. It is not atomic.
/// Tasks may appear while we are traversing the tree.
pub fn kill_process_tree(root_pid: i32, signal: Signal) -> Result<()> {
    // The application is running under a process group (pid=APP_ROOT_PID)
    // Normally we should be able to just kill that, but because the application
    // can call setsid() and setpgrp(), then we might not get processes as process
    // groups don't nest. So we need to iterate through all children.
    // We gather process groups of all children, and kill these.
    let mut pgrp_pids: HashSet::<i32> = HashSet::new();

    for pid in get_process_tree(root_pid)? {
        // We tolerate open failures as tasks may disappear.
        if let Ok(file) = File::open(Path::new("/proc").join(pid.to_string()).join("status")) {
            for line in BufReader::new(file).lines() {
                // lines are of the format "Key:\tValue"
                // The NSpgid line may have multiple pids separated with a \t. We only
                // care about the first one, hence the .. at the end of the pattern match.
                if let &[key, value, ..] = &*line?.split(":\t").collect::<Vec<_>>() {
                    if key == "NSpgid" {
                        pgrp_pids.insert(value.parse().expect("non-numeric pid"));
                        break; // stop reading the status file, we have what we want.
                    }
                }
            }
        }
    }

    ensure!(!pgrp_pids.is_empty(), "Failed to parse process groups in /proc");

    for pid in pgrp_pids {
        // We ignore kill errors as process may disappear.
        // It's not really satisfactory, but I'm not sure if we can do better.
        let _ = killpg(Pid::from_raw(pid), signal);
    }

    Ok(())
}
