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
    /// The list of children. It is used in append only mode. Children are never
    /// removed or reordered. This is important for the integrity of `ProcessHandle`.
    children: Vec<ProcessMembership>,
    /// When `ProcessGroup` is dropped, it sends a SIGTERM to the remaining
    /// killable children. After kill_grace_period has elapsed, it sends a SIGKILL.
    kill_grace_period: Duration,
    /// Something to remember for unregistering the sigchld_pipe SIGCHLD.
    sig_hook_id: Option<signal_hook::SigId>,
}

pub struct ProcessMembership {
    inner: Process,
    /// Once a process has exited, we no longer poll its status.
    /// We keep the process around because of the get_mut() API.
    exited: bool,
    /// When the process is marked as killable, it means that the process monitor
    /// can kill it on drop(). This is useful to make CRIU immune to kills as it
    /// could leave the application in a bad state.
    killable: bool,
    /// When the process is marked as daemon, it means that the process monitor
    /// won't wait for this process to exit in wait_for_success().
    daemon: bool,
}

/// `ProcessHandle` represents a specific child. It contains the index of the
/// child located in the `children` array. The handle is returned by `add()`, and
/// used in `get_mut()`.
#[derive(Clone, Copy, Debug)]
pub struct ProcessHandle(usize);

impl From<Process> for ProcessMembership {
    fn from(inner: Process) -> Self {
        Self { inner, exited: false, killable: true, daemon: false }
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
        let sig_hook_id = Some(signal_hook::low_level::pipe::register(
                                signal_hook::consts::SIGCHLD, pipe.write)
            .context("Failed to register signal")?);

        Ok(Self {
            sigchld_pipe: pipe.read,
            children: Vec::new(),
            kill_grace_period,
            sig_hook_id,
        })
    }

    pub fn add(&mut self, proc: impl Into<ProcessMembership>) -> ProcessHandle {
        self.children.push(proc.into());
        ProcessHandle(self.children.len() - 1)
    }

    pub fn get_mut(&mut self, id: ProcessHandle) -> &mut Process {
        &mut self.children[id.0].inner
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
        for child in &mut self.children {
            if child.inner.try_wait()?.is_some() { // has child exited ?
                child.exited = true;
                if let Err(err) = child.inner.wait_for_success() { // has child errored ?
                    errors.push(err.downcast::<ProcessError>()?);
                }
            }
        }

        if !errors.is_empty() {
           bail!(ProcessGroupError { errors });
        }

        Ok(self.children.iter().any(|c| !c.exited && !c.daemon))
    }

    pub fn poll_fds(&self) -> Vec<PollFd> {
        // Collect all the fd of the stderr that we should be monitoring
        // with the fd of the sigchld. Drainage of stderrs happens in
        // child.inner.try_wait() within try_wait_for_success().
        self.children.iter()
            .filter_map(|c| c.inner.stderr_logger_fd())
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

    pub fn terminate(&mut self) -> Result<()> {
        // Step 1: SIGTERM all killable children
        let mut killables = self.children.iter_mut()
            .filter(|c| c.killable && !c.exited)
            .collect::<Vec<_>>();

        for child in &mut killables {
            if child.inner.try_wait()?.is_none() {
                // try_wait() returned none, so the child is not reaped (it is
                // potentially in a zombie state), and thus kill() should not fail.
                child.inner.kill(signal::SIGTERM)?;
            }
        }

        // Step 2: SIGKILL all killable children that haven't exited
        // within the kill_grace_period.
        let deadline = Instant::now() + self.kill_grace_period;
        for child in &mut killables {
            if child.inner.wait_timeout(deadline)?.is_none() {
                // kill() should not fail as the child is still not reaped
                child.inner.kill(signal::SIGKILL)?;
            }
        }

        // Step 3: wait for all children to exit, including non-killable
        // children.
        for child in &mut self.children {
            child.inner.wait()?;
            child.exited = true;
        }

        // Cleanup the SIGCHLD hook.
        if let Some(sig_hook_id) = self.sig_hook_id.take() {
            ensure!(signal_hook::low_level::unregister(sig_hook_id),
                    "signal_hook failed to unregister");
        }
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
    fn join(self, pgrp: &mut ProcessGroup) -> ProcessHandle;
    fn join_as_non_killable(self, pgrp: &mut ProcessGroup) -> ProcessHandle;
    fn join_as_daemon(self, pgrp: &mut ProcessGroup) -> ProcessHandle;
}

impl ProcessExt for Process {
    fn join(self, pgrp: &mut ProcessGroup) -> ProcessHandle {
        pgrp.add(self)
    }
    fn join_as_non_killable(self, pgrp: &mut ProcessGroup) -> ProcessHandle {
        pgrp.add(ProcessMembership::from(self).non_killable())
    }
    fn join_as_daemon(self, pgrp: &mut ProcessGroup) -> ProcessHandle {
        pgrp.add(ProcessMembership::from(self).daemon())
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
        let mut pgrp = new_process_group()?;
        pgrp.add(Command::new(&["true"]).spawn()?);
        pgrp.add(Command::new(&["sleep"]).arg("0.2").spawn()?);
        pgrp.wait_for_success()
    }

    #[test]
    fn test_exit_fail() -> Result<()> {
        let mut pgrp = new_process_group()?;
        pgrp.add(Command::new(&["true"]).spawn()?);
        pgrp.add(Command::new(&["sleep"]).arg("1000").spawn()?);
        pgrp.add(Command::new(&["false"]).spawn()?);
        let err_msg = pgrp
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

        let mut pgrp = new_process_group()?;
        pgrp.add(cmd1);
        pgrp.add(cmd2);
        pgrp.add(cmd3);
        let err_msg = pgrp
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

        let mut pgrp = new_process_group()?;
        pgrp.add(cmd);
        let err_msg = pgrp
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

        println!("elapsed time {}ms", start_time.elapsed().as_millis());
        assert!(start_time.elapsed().as_millis() >= 1000);

        Ok(())
    }

    #[test]
    fn test_daemon() -> Result<()> {
        let start_time = Instant::now();
        let mut pgrp = new_process_group()?;

        Command::new(&["sleep", "1000"]).spawn()?
            .join_as_daemon(&mut pgrp);

        pgrp.wait_for_success()?;

        println!("elapsed time {}ms", start_time.elapsed().as_millis());
        assert!(start_time.elapsed().as_secs() < 1000);

        Ok(())
    }

    #[test]
    fn test_get_mut() -> Result<()> {
        let mut cmd1 = Command::new(&["bash", "-c", "exit 2"]).spawn()?;
        let mut cmd2 = Command::new(&["false"]).spawn()?;

        cmd1.wait()?;
        cmd2.wait()?;

        let mut pgrp = new_process_group()?;
        let ps1 = pgrp.add(cmd1);
        let ps2 = pgrp.add(cmd2);

        // processes should still be accessible after terminate()
        pgrp.terminate()?;

        assert_eq!(pgrp.get_mut(ps1).wait()?.code().unwrap(), 2);
        assert_eq!(pgrp.get_mut(ps2).wait()?.code().unwrap(), 1);

        Ok(())
    }
}
