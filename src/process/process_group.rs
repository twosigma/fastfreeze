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
    os::unix::io::AsRawFd,
    io::{ErrorKind, Read},
    time::{Duration, Instant},
    fs, iter,
};
use nix::{
    poll::{PollFd, PollFlags},
    fcntl::OFlag,
    sys::signal,
};
use crate::{
    consts::*,
    util::{poll_nointr, Pipe},
};
use super::{Process, ProcessError, ProcessGroupError};

/// `ProcessGroup` is used for monitoring a group of processes.
/// When dropped, the whole group is killed, except non-killable children.
pub struct ProcessGroup {
    /// We use a pipe to process SIGCHLD, because at some point we need to select()
    /// on a pipe and watch for children to fail simultaneously.
    sigchld_pipe: fs::File,
    /// The list of children. When a child terminates, it is taken out from the list.
    children: Vec<ProcessMembership>,
    /// When `ProcessGroup` is dropped, it sends a SIGTERM to the remaining
    /// killable children. After kill_grace_period has elapsed, it sends a SIGKILL.
    kill_grace_period: Duration,
    /// Something to remember for unregistering the sigchld_pipe SIGCHLD.
    sig_hook_id: signal_hook::SigId,
}

pub struct ProcessMembership {
    inner: Process,
    /// When the process is marked as killable, it means that the process monitor
    /// can kill it on drop(). This is useful to make CRIU immune to kills as it
    /// could leave the application in a bad state.
    killable: bool,
    /// When the process is marked as daemon, it means that the process monitor
    /// won't wait for this process to exit in wait_for_success().
    daemon: bool,
}

impl From<Process> for ProcessMembership {
    fn from(inner: Process) -> Self {
        Self { inner, killable: true, daemon: false }
    }
}

impl ProcessMembership {
    pub fn non_killable(self) -> Self {
        Self { killable: false, ..self }
    }
    pub fn daemon(self) -> Self {
        Self { daemon: true, ..self }
    }
}

impl ProcessGroup {
    pub fn new() -> Result<Self> {
        Self::with_kill_grace_period(Duration::from_secs(KILL_GRACE_PERIOD_SECS))
    }

    pub fn with_kill_grace_period(kill_grace_period: Duration) -> Result<Self> {
        let pipe = Pipe::new(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
        let sig_hook_id = signal_hook::pipe::register(signal_hook::SIGCHLD, pipe.write)
            .context("Failed to register signal")?;

        Ok(Self {
            sigchld_pipe: pipe.read,
            children: Vec::new(),
            kill_grace_period,
            sig_hook_id,
        })
    }

    pub fn add(&mut self, proc: impl Into<ProcessMembership>) -> &mut Self {
        self.children.push(proc.into());
        self
    }

    pub fn last_mut(&mut self) -> Option<&mut Process> {
        self.children.last_mut().map(|membership| &mut membership.inner)
    }

    fn drain_sigchld_pipe(&mut self) {
        // Discard the content of the pipe
        let mut vec = Vec::new();
        match self.sigchld_pipe.read_to_end(&mut vec) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            result => { result.expect("SIGCHLD pipe has draining issues"); }
        }
    }

    /// Returns an error if a process has exited with a failure.
    /// Return Ok(true) if some children are remaining, Ok(false) otherwise.
    pub fn try_wait_for_success(&mut self) -> Result<bool> {
        self.drain_sigchld_pipe();

        // We join the error messages of all errored children.
        // This is useful when running pipe-connected processes like
        // "A | B" where both processes are dependent on the other.
        // When one dies, the other dies too. But we don't know which
        // one died first. So we report both errors.
        let mut errors = Vec::new();
        let children = std::mem::replace(&mut self.children, Vec::new());
        for mut child in children {
            if child.inner.try_wait()?.is_some() { // has child exited ?
                if let Err(err) = child.inner.wait_for_success() { // has child errored ?
                    errors.push(err.downcast::<ProcessError>()?);
                }
            } else {
                self.children.push(child);
            }
        }

        if !errors.is_empty() {
           bail!(ProcessGroupError { errors });
        }

        Ok(self.children.iter().any(|c| !c.daemon))
    }

    pub fn poll_fds(&self) -> Vec<PollFd> {
        // Collect all the fd of the stderr that we should be monitoring
        // with the fd of the sigchld. Drainage of stderrs happens in
        // child.inner.try_wait() within try_wait_for_success().
        self.children.iter()
            .filter_map(|c| c.inner.stderr_logger.as_ref())
            .map(|sl| sl.stderr_fd)
            .chain(iter::once(self.sigchld_pipe.as_raw_fd()))
            .map(|fd| PollFd::new(fd, PollFlags::POLLIN))
            .collect()
    }

    pub fn wait_for_success(&mut self) -> Result<()> {
        while self.try_wait_for_success()? {
            let timeout = -1;
            poll_nointr(&mut self.poll_fds(), timeout)
                .context("Failed to poll()")?;
        }
        Ok(())
    }

    fn terminate_killable_gracefully(&mut self) -> Result<()> {
        let (mut killables, non_killables) = self.children.drain(..)
            .partition(|c| c.killable);

        self.children = non_killables;

        for child in &mut killables {
            if child.inner.try_wait()?.is_none() {
                // Sending the signal should not fail as our child is not reaped
                // as try_wait() returned is none.
                child.inner.kill(signal::SIGTERM)?;
            }
        }

        let deadline = Instant::now() + self.kill_grace_period;
        for child in &mut killables {
            if child.inner.wait_timeout(deadline)?.is_none() {
                // Child didn't exit in time, it is getting a SIGKILL.
                // kill() should not failed as our child is not reaped.
                child.inner.kill(signal::SIGKILL)?;
                child.inner.wait()?;
            }
        }

        Ok(())
    }

    pub fn terminate(&mut self) -> Result<()> {
        self.terminate_killable_gracefully()?;
        for child in &mut self.children {
            child.inner.wait()?;
        }
        ensure!(signal_hook::unregister(self.sig_hook_id),
                "signal_hook failed to unregister");
        Ok(())
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = self.terminate()
            .map_err(|e| error!("Skipping children termination: {}", e));
    }
}

pub trait ProcessExt {
    fn join(self, pgrp: &mut ProcessGroup);
    fn join_as_non_killable(self, pgrp: &mut ProcessGroup);
    fn join_as_daemon(self, pgrp: &mut ProcessGroup);
}

impl ProcessExt for Process {
    fn join(self, pgrp: &mut ProcessGroup) {
        pgrp.add(self);
    }
    fn join_as_non_killable(self, pgrp: &mut ProcessGroup) {
        pgrp.add(ProcessMembership::from(self).non_killable());
    }
    fn join_as_daemon(self, pgrp: &mut ProcessGroup) {
        pgrp.add(ProcessMembership::from(self).daemon());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::*;

    use nix::sys::signal::Signal;

    fn new_process_group() -> Result<ProcessGroup> {
        let kill_grace_period = Duration::from_secs_f32(0.3);
        ProcessGroup::with_kill_grace_period(kill_grace_period)
    }

    #[test]
    fn test_basic_kill() -> Result<()> {
       let mut pgrp = new_process_group()?;
       Command::new(&["sleep", "1000"])
            .spawn()?
            .join(&mut pgrp);
        // drops and kills sleep
        Ok(())
    }

    #[test]
    fn test_wait_success() -> Result<()> {
        new_process_group()?
            .add(Command::new(&["true"]).spawn()?)
            .add(Command::new(&["sleep"]).arg("0.2").spawn()?)
            .wait_for_success()
    }

    #[test]
    fn test_exit_fail() -> Result<()> {
        let err_msg = new_process_group()?
            .add(Command::new(&["true"]).spawn()?)
            .add(Command::new(&["sleep"]).arg("1000").spawn()?)
            .add(Command::new(&["false"]).spawn()?)
            .wait_for_success()
            .unwrap_err()
            .to_string();

        dbg!(&err_msg);
        assert!(err_msg.contains("false"));
        assert!(err_msg.contains("exit_code=1"));

        Ok(())
    }

    #[test]
    fn test_exit_fail_multiple() -> Result<()> {
        let mut cmd1 = Command::new(&["bash", "-c", "exit 2"]).spawn()?;
        let mut cmd2 = Command::new(&["false"]).spawn()?;
        let cmd3 = Command::new(&["sleep"]).arg("1000").spawn()?;

        cmd1.wait()?;
        cmd2.wait()?;

        let err_msg = new_process_group()?
            .add(cmd1)
            .add(cmd2)
            .add(cmd3)
            .wait_for_success()
            .unwrap_err()
            .to_string();

        dbg!(&err_msg);
        assert!(err_msg.contains("bash"));
        assert!(err_msg.contains("exit_code=2"));
        assert!(err_msg.contains("false"));
        assert!(err_msg.contains("exit_code=1"));

        Ok(())
    }

    #[test]
    fn test_signaled() -> Result<()> {
        let cmd = Command::new(&["sleep", "1000"]).spawn()?;
        cmd.kill(Signal::SIGTERM)?;

        let err_msg = new_process_group()?
            .add(cmd)
            .wait_for_success()
            .unwrap_err()
            .to_string();

        dbg!(&err_msg);
        assert!(err_msg.contains("sleep"));
        assert!(err_msg.contains("caught fatal SIGTERM"));

        Ok(())
    }

    #[test]
    fn test_unkillable() -> Result<()> {
        let start_time = Instant::now();

        let mut pgrp = new_process_group()?;

        Command::new(&["sleep", "1"]).spawn()?
            .join_as_non_killable(&mut pgrp);

        drop(pgrp);

        assert!(start_time.elapsed().as_millis() > 1000);

        Ok(())
    }

    #[test]
    fn test_daemon() -> Result<()> {
        let start_time = Instant::now();
        let mut pgrp = new_process_group()?;

        Command::new(&["sleep", "1000"]).spawn()?
            .join_as_daemon(&mut pgrp);

        pgrp.wait_for_success()?;

        assert!(start_time.elapsed().as_secs() < 1000);

        Ok(())
    }
}
