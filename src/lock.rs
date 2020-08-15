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
    time::{Instant, Duration},
    path::Path,
    fs,
};
use nix::{
    Error,
    errno::Errno,
    fcntl::{flock, FlockArg}
};
use crate::{
    consts::*,
    signal::check_for_pending_sigterm,
};

#[must_use = "if unused, the lock will immediately unlock"]
/// When `FileLockGuard` is dropped, the corresponding `fs::File` is closed, unlocking the file.
pub struct FileLockGuard(fs::File);

#[derive(Debug)]
struct LockTimeoutError;
impl std::error::Error for LockTimeoutError {}
impl std::fmt::Display for LockTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Lock timeout exeeded")
    }
}

pub fn file_lock(path: &Path, timeout: Option<Instant>, exclusive: bool)
    -> Result<FileLockGuard>
{
    // Instead of using alarm() to support timeout, we use the non-blocking
    // version of flock to avoid races.
    let flag = match (timeout.is_some(), exclusive) {
        (true,  true)  => FlockArg::LockExclusiveNonblock,
        (true,  false) => FlockArg::LockSharedNonblock,
        (false, true)  => FlockArg::LockExclusive,
        (false, false) => FlockArg::LockShared,
    };

    let file = fs::File::create(path)
        .with_context(|| format!("Failed to create lock file {}. \
                                  Run `fastfreeze install` first", path.display()))?;

    trace!("Waiting to acquire file lock at {}", path.display());

    loop {
        check_for_pending_sigterm()?;

        match (flock(file.as_raw_fd(), flag), timeout.as_ref()) {
            (Err(Error::Sys(Errno::EAGAIN)), Some(timeout)) => {
                ensure!(Instant::now() < *timeout, LockTimeoutError);
                std::thread::sleep(Duration::from_millis(100));
            },
            (Err(Error::Sys(Errno::EINTR)), _) => {},
            (Err(e), _) => bail!(e),
            (Ok(_), _) => break,
        }
    }

    Ok(FileLockGuard(file))
}

pub fn checkpoint_restore_lock(timeout: Option<Instant>, exclusive: bool)
    -> Result<FileLockGuard>
{
    file_lock(&*LOCK_FILE_PATH, timeout, exclusive).map_err(|e|
        match e.downcast::<LockTimeoutError>() {
            Ok(_) => anyhow!("Previous checkpoint/restore operation still in progress"),
            Err(e) => e,
        }
    )
}

pub fn with_checkpoint_restore_lock<F,R>(f: F) -> Result<R>
    where F: FnOnce() -> Result<R>,
{
    let _lock_guard = {
        // We use a 1 second timeout because we could be racing with a "fastfreeze
        // wait" command, which holds the lock for a tiny amount of time. Otherwise,
        // we would use 0 timeout.
        let timeout = Some(Instant::now() + Duration::from_secs(1));
        checkpoint_restore_lock(timeout, true)?
    };

    f()
}
