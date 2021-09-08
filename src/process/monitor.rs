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
use nix::{
    sys::signal::{kill, pthread_sigmask, Signal, SigmaskHow, SigSet},
    sys::wait::{wait, WaitStatus},
    unistd::Pid
};
use crate::cli::ExitCode;


#[derive(Debug)]
pub enum ChildDied {
    Exited(u8),
    Signaled(Signal),
}

impl std::error::Error for ChildDied {}
impl std::fmt::Display for ChildDied {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ChildDied::Exited(exit_code) => write!(f, "Application exited with exit_code={}", exit_code),
            ChildDied::Signaled(signal) => write!(f, "Application caught fatal signal {}", signal),
        }
    }
}


/// `monitor_child()` monitors a child (good for assuming the init role).
/// We do the following:
/// 1) We proxy signals we receive to our `pid_child`
/// 2) We reap processes that get reparented to us, although this should not happen for
///    the application process tree, as we set PR_SET_CHILD_SUBREAPER on the application root process.
/// 3) When `pid_child` dies, we return an error that contains the appropriate exit_code.
///    If the child exited normally, we return Ok(()).
/// XXX We don't unregister signals after this function. The caller is expected to exit right after.
pub fn monitor_child(pid_child: Pid) -> Result<()> {
    use libc::c_int;

    for sig in Signal::iterator() {
        // We don't forward SIGCHLD, and neither `FORBIDDEN` signals (e.g.,
        // SIGSTOP, SIGFPE, SIGKILL, ...)
        if sig == Signal::SIGCHLD || signal_hook::consts::FORBIDDEN.contains(&(sig as c_int)) {
            continue;
        }

        // Forward signal to our child.
        // The `register` function is unsafe because one could call malloc(),
        // and deadlock the program. Here we call kill() which is safe.
        unsafe {
            signal_hook::low_level::register(sig as c_int, move || {
                let _ = kill(pid_child, sig);
            })?;
        }
    }
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&SigSet::all()), None)?;

    loop {
        match wait().with_context(|| format!("Failed to wait for child pid={}", pid_child))? {
            WaitStatus::Exited(pid, 0) if pid == pid_child => {
                return Ok(());
            }
            WaitStatus::Exited(pid, exit_status) if pid == pid_child => {
                // When the monitored application dies, the children if any, will get
                // reparented to us (or whoever is the init process).
                // That's fine. We are going to exit, and the container will die, killing
                // all the orphans.
                return Err(anyhow!(ChildDied::Exited(exit_status as u8))
                    .context(ExitCode(exit_status as u8)));
            }
            WaitStatus::Signaled(pid, signal, _core_dumped) if pid == pid_child => {
                return Err(anyhow!(ChildDied::Signaled(signal))
                    .context(ExitCode(128 + signal as u8)));
            }
            _ => {},
        };
    }
}
