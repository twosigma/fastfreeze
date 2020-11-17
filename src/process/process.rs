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
    time::{Duration, Instant},
};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};

pub use std::process::{
    ExitStatus,
    Stdio,
    ChildStdin,
    ChildStdout,
    ChildStderr,
    Output as StdOutput,
    Child
};
use crate::signal::{check_for_pending_sigterm, retry_on_interrupt};
use super::{
    stderr_logger::StderrLogger,
    error::StderrTail,
    ProcessError,
};

// We create our own `Child` wrapper to provide better error context.
// We further expose a slightly different API than what is offered from the stdlib.
// to incorporate SIGTERM monitoring, and helpful error messages

pub struct Process {
    inner: Child,
    display_cmd: String,
    pub stderr_logger: Option<StderrLogger>,
}

impl Process {
    pub fn new(mut inner: Child, display_cmd: String, stderr_log_prefix: Option<&'static str>) -> Self {
        let stderr_logger = stderr_log_prefix.map(|prefix|
             StderrLogger::new(prefix, inner.stderr.take().expect("stderr not captured"))
        );
        Self { inner, display_cmd, stderr_logger }
    }

    pub fn pid(&self) -> i32 { self.inner.id() as i32 }

    pub fn kill(&self, signal: Signal) -> Result<()> {
        signal::kill(Pid::from_raw(self.pid()), signal)
            .with_context(|| format!("Failed to signal pid={}", self.pid()))
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        check_for_pending_sigterm()?;
        let result = self.inner.try_wait()
            .with_context(|| format!("wait(pid={}) failed", self.pid()));
        // We drain the stderr after the process may have exited. It ensures we
        // drain every last bit of it (under the assumption that the process
        // didn't leak its stderr to another process).
        self.drain_stderr_logger();
        result
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        retry_on_interrupt(|| {
            check_for_pending_sigterm()?;
            // We wait for the process to exit, but at the same time we must
            // drain its stderr. It's a bit painful to do it well with POSIX.
            // Instead, we'll make a blocking stderr read.
            // XXX We make the assumption that the process doesn't leak its
            // stderr to another process. Otherwise, we could be blocking forever,
            // even though the process has died.
            self.stderr_logger.as_mut().map(|sl| sl.set_blocking(true).drain());
            self.inner.wait()
                .with_context(|| format!("wait(pid={}) failed", self.pid()))
        })
    }

    pub fn wait_timeout(&mut self, until: Instant) -> Result<Option<ExitStatus>> {
        loop {
            if let Some(exit_status) = self.try_wait()? {
                return Ok(Some(exit_status));
            }

            if Instant::now() > until {
                return Ok(None);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn wait_for_success(&mut self) -> Result<()> {
        let exit_status = self.wait()?;
        ensure_successful_exit_status(
            exit_status, self.display_cmd.clone(), self.stderr_logger.as_ref())
    }

    pub fn wait_with_output(self) -> Result<Output> {
        let Process { display_cmd, inner, stderr_logger } = self;

        assert!(stderr_logger.is_none(),
                "stderr logging is not supported when using wait_with_output()");

        // FIXME `wait_with_output()` can read from stderr, and stdout and
        // ignore if we received a SIGTERM. That's because `read_to_end()` is
        // used internally, and ignores EINTR.
        // That means that we won't act on SIGTERM.
        check_for_pending_sigterm()?;
        let result = inner.wait_with_output()?;

        Ok(Output {
            status: result.status,
            stdout: result.stdout,
            stderr: result.stderr,
            display_cmd,
        })
    }

    pub fn drain_stderr_logger(&mut self) {
        self.stderr_logger.as_mut().map(|sl| sl.drain());
    }

    pub fn reap_on_drop(self) -> ProcessDropReaper {
        ProcessDropReaper { inner: self }
    }

    // In the following, unwrap() is okay. It would be a logic error to access
    // these without having setup the corresponding pipe.
    pub fn stdin(&mut self) -> &mut ChildStdin { self.inner.stdin.as_mut().unwrap() }
    pub fn stdout(&mut self) -> &mut ChildStdout { self.inner.stdout.as_mut().unwrap() }
    pub fn stderr(&mut self) -> &mut ChildStderr { self.inner.stderr.as_mut().unwrap() }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> { self.inner.stdin.take() }
}

pub struct ProcessDropReaper {
    inner: Process,
}

impl Drop for ProcessDropReaper {
    fn drop(&mut self) {
        // If the process fails, we log the error and move on.
        let _ = self.inner.wait_for_success()
            .map_err(|e| error!("{}", e));
    }
}

pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub display_cmd: String,
}

impl Output {
    pub fn ensure_success(&self) -> Result<()> {
        ensure_successful_exit_status(self.status, self.display_cmd.clone(), None)
    }

    pub fn ensure_success_with_stderr_log(&self, log_prefix: &'static str) -> Result<()> {
        if self.status.success() {
            Ok(())
        } else {
            let stderr_tail = String::from_utf8_lossy(&self.stderr)
                .lines()
                .map(|l| l.into())
                .collect();

            bail!(ProcessError {
                exit_status: self.status,
                display_cmd: self.display_cmd.clone(),
                stderr_tail: Some(StderrTail { log_prefix, stderr_tail }),
            });
        }
    }
}

fn ensure_successful_exit_status(
    exit_status: ExitStatus,
    display_cmd: String,
    stderr_logger: Option<&StderrLogger>
) -> Result<()> {
    if exit_status.success() {
        Ok(())
    } else {
        let stderr_tail = stderr_logger.map(|sl| sl.into());
        bail!(ProcessError { exit_status, display_cmd, stderr_tail })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::*;

    #[test]
    fn test_shell() -> Result<()> {
        let mut cmd = Command::new_shell("exit `echo 33`").spawn()?;
        let err_msg = cmd.wait_for_success().unwrap_err().to_string();

        dbg!(&err_msg);
        assert!(err_msg.contains("exit `echo 33`"));
        assert!(err_msg.contains("exit_code=33"));

        Ok(())
    }

    #[test]
    fn test_args() -> Result<()> {
        let out = Command::new(&["echo", "-n", "hello"])
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()?
            .stdout;

        assert_eq!(String::from_utf8_lossy(&out), "hello");

        Ok(())
    }
}
