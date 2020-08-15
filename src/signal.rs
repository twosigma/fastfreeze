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
    io::ErrorKind,
};
use nix::errno::Errno;
use nix::sys::signal;

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
    if SIGTERM_RECEIVED.fetch_and(false, Ordering::SeqCst) {
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
