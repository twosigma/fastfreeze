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

use anyhow::{Result, Error};
use std::{
    os::unix::io::{AsRawFd, RawFd},
    collections::VecDeque,
    io::{BufReader, BufRead, ErrorKind},
};
use nix::{
    fcntl::OFlag,
    fcntl::{fcntl, FcntlArg},
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
use crate::{
    consts::*,
};

// We create our own `Child` wrapper to provide better error context.
// We further expose a slightly different API than what is offered from the stdlib.
// to incorporate SIGTERM monitoring, and helpful error messages


pub struct StderrLogger {
    pub log_prefix: &'static str,
    /// We buffer the last few lines of stderr so that we can emit metrics with the
    /// stderr of the process.
    backlog: VecDeque<Box<str>>,
    stderr: BufReader<ChildStderr>,
    pub stderr_fd: RawFd,
}

impl StderrLogger {
    pub fn new(log_prefix: &'static str, stderr: ChildStderr) -> Self {
        let stderr_fd = stderr.as_raw_fd();
        let stderr = BufReader::new(stderr);
        let backlog = VecDeque::with_capacity(STDERR_TAIL_NUM_LINES);
        let mut self_ = Self { log_prefix, backlog, stderr, stderr_fd };
        self_.set_blocking(false);
        self_
    }

    pub fn set_blocking(&mut self, blocking: bool) -> &mut Self {
        let flag = if blocking { OFlag::empty() } else { OFlag::O_NONBLOCK };
        fcntl(self.stderr_fd, FcntlArg::F_SETFL(flag))
            .expect("Failed to fcntl() on stderr");
        self
    }

    pub fn drain(&mut self) -> Result<()> {
        // Read all lines until we reach an -EAGAIN
        // Each line is emitted to the logs, and saved into the backlog
        let mut line = String::new();
        loop {
            // XXX there's no bounds on the line size. If we don't get a "\n"
            // when reading stderr, we can blow up in memory utilization.
            // It's a risk we are willing to take, given that we assume the
            // programs we run (tar, criu) are well behaved.
            match self.stderr.read_line(&mut line) {
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => bail!(self.format_read_error(anyhow!(err), &line)),
                Ok(0) => break, // Reached EOF
                Ok(_) => self.log_line(&line),
            }
            line.clear();
        }

        Ok(())
    }

    fn log_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        info!("{}> {}", self.log_prefix, line);

        if self.backlog.len() == self.backlog.capacity() {
            self.backlog.pop_front();
        }
        self.backlog.push_back(line.into());
    }

    fn format_read_error(&self, err: Error, line: &str) -> Error {
        let mut e = anyhow!(err).context(
            format!("Failed to read stderr from `{}`", self.log_prefix));
        if !line.is_empty() {
            e = e.context(format!("Partial stderr read : `{}`", line));
        }
        e
    }

    pub fn get_stderr_tail(&self) -> Vec<Box<str>> {
        // We do a copy, and that seems inefficient, but that simplifies the error
        // code compared to having an Rc<>. This code path is not performance critical.
        self.backlog.iter().map(|line| line.clone()).collect()
    }
}
