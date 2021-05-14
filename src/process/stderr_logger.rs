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
    borrow::Cow,
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

pub struct StderrReader {
    reader: BufReader<ChildStderr>,
    pub fd: RawFd,
}

impl StderrReader {
    pub fn new(stderr: ChildStderr) -> Self {
        let fd = stderr.as_raw_fd();
        let reader = BufReader::new(stderr);
        let mut self_ = Self { reader, fd };
        self_.set_blocking(false);
        self_
    }

    pub fn set_blocking(&mut self, blocking: bool) -> &mut Self {
        let flag = if blocking { OFlag::empty() } else { OFlag::O_NONBLOCK };
        fcntl(self.fd, FcntlArg::F_SETFL(flag))
            .expect("Failed to fcntl() on stderr");
        self
    }

    pub fn drain(&mut self, tail: &mut StderrTail) -> Result<()> {
        // Read all lines until we reach an -EAGAIN
        // Each line is emitted to the logs, and saved into the backlog
        let mut line = String::new();
        loop {
            // XXX there's no bounds on the line size. If we don't get a "\n"
            // when reading stderr, we can blow up in memory utilization.
            // It's a risk we are willing to take, given that we assume the
            // programs we run (tar, criu) are well behaved.
            match self.reader.read_line(&mut line) {
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => bail!(self.format_read_error(anyhow!(err), &tail.log_prefix, &line)),
                Ok(0) => break, // Reached EOF
                Ok(_) => tail.log_line(&line),
            }
            line.clear();
        }

        Ok(())
    }

    fn format_read_error(&self, err: Error, log_prefix: &str, line: &str) -> Error {
        let mut e = anyhow!(err).context(
            format!("Failed to read stderr from `{}`", log_prefix));
        if !line.is_empty() {
            e = e.context(format!("Partial stderr read : `{}`", line));
        }
        e
    }
}

#[derive(Clone, Debug)]
pub struct StderrTail {
    pub log_prefix: Cow<'static, str>,
    /// We buffer the last few lines of stderr so that we can emit metrics with the
    /// stderr of the process.
    pub tail: VecDeque<Box<str>>,
}

impl StderrTail {
    pub fn new(log_prefix: Cow<'static, str>) -> Self {
        let tail = VecDeque::with_capacity(STDERR_TAIL_NUM_LINES);
        Self { log_prefix, tail }
    }

    fn log_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }

        info!("{}> {}", self.log_prefix, line);

        if self.tail.len() == self.tail.capacity() {
            self.tail.pop_front();
        }
        self.tail.push_back(line.into());
    }
}
