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
    error::Error,
    fmt::Display,
    fs::File,
    io::{BufReader, ErrorKind},
    path::Path,
    result::Result as StdResult,
    sync::atomic::{AtomicBool, Ordering}
};
use std::io::prelude::*;
use nix::{
    sys::signal::{self, kill, Signal},
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
            signal_hook::low_level::register(*signal as i32, ||
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
        matches!(&self, Self::Sys(errno) if *errno == Errno::EINTR)
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

fn get_children(pid: Pid) -> Result<Vec<Pid>> {
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
        .map(|pid| Pid::from_raw(pid.parse::<i32>().expect("non-numeric pid")))
        .collect())
}

fn get_process_tree(root_pid: Pid) -> Result<Vec<Pid>> {
    fn get_process_tree_inner(pid: Pid, pids: &mut Vec<Pid>) -> Result<()> {
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
/// This is mostly used to SIGSTOP/SIGCONT the entire application.
/// TODO We could use the cgroup freezer if we have access to it.
pub fn kill_process_tree(root_pid: Pid, signal: Signal) -> Result<()> {
    for pid in get_process_tree(root_pid)? {
        // We ignore kill errors as process may disappear.
        // It's not really satisfactory, but I'm not sure if we can do better.
        let _ = kill(pid, signal);
    }

    Ok(())
}

pub fn get_proc_state(pid: Pid) -> Result<char> {
    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let status_file = File::open(status_path)?;

    for line in BufReader::new(status_file).lines() {
        // lines are of the format "Key:\tValue"
        // We are looking for the state line "State:  R (running)"
        if let [key, value] = *line?.split(":\t").collect::<Vec<_>>() {
            if key == "State" {
                return Ok(value.chars().next().expect("proc status file corrupted"));
            }
        }
    }

    bail!("Failed to parse proc status file");
}
