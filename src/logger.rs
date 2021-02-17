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
    io::prelude::*,
    io::stderr,
    sync::Mutex,
    fs,
    path::{Path, PathBuf},
};
use log::{Record, Metadata};
pub use log::LevelFilter;
use chrono::prelude::*;
use crate::{
    consts::*,
    util::{create_dir_all, set_tmp_like_permissions},
};

pub struct Logger {
    cmd_name: &'static str,
    log_file: Option<(fs::File, PathBuf)>,
    stdout_enabled: bool,
}

impl Logger {
    fn log(&mut self, record: &Record) {
        let msg = format!("[ff.{}] ({:.3}s) {}\n",
            self.cmd_name, START_TIME.elapsed().as_secs_f64(), record.args());

        // When we fail to write to the outputs, we dismiss the errors.
        // Maybe there's something better to do.
        if self.stdout_enabled {
            let _ = stderr().write_all(msg.as_bytes());
        }
        let _ = self.log_file.as_mut().map(|f| f.0.write_all(msg.as_bytes()));
    }

    fn flush(&mut self) {
        let _ = stderr().flush();
        let _ = self.log_file.as_mut().map(|f| f.0.flush());
    }

    fn move_file(&mut self, directory: &Path) -> Result<()> {
        if let Some((old_file, old_path)) = self.log_file.take() {
            // unwrap() is safe here: we always have a log filename
            let new_path = directory.join(old_path.file_name().unwrap());

            // We first attempt to rename the log file. If we fail due to
            // moving a file cross-device, we copy, and re-open.
            self.log_file = Some(match fs::rename(&old_path, &new_path) {
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                    // We are moving the file cross devices. So we need to do a
                    // copy, followed by re-opening the file.
                    fs::copy(&old_path, &new_path).with_context(|| format!(
                        "Failed to copy {} to {}", old_path.display(), new_path.display()))?;
                    let new_file = fs::OpenOptions::new()
                        .append(true)
                        .open(&new_path)
                        .with_context(|| format!("Failed to re-open log file at {}", new_path.display()))?;
                    fs::remove_file(&old_path)
                        .with_context(|| format!("Failed to unlink {}", old_path.display()))?;
                    (new_file, new_path)
                },
                Err(e) => Err(e).with_context(|| format!(
                    "Failed to rename {} to {}", old_path.display(), new_path.display()))?,
                Ok(()) => (old_file, new_path),
            })
        }
        Ok(())
    }
}

lazy_static! {
    static ref LOGGER: Mutex<Option<Logger>> = Mutex::new(None);
}

pub fn move_log_file(directory: &Path) -> Result<()> {
    if let Some(logger) = LOGGER.lock().unwrap().as_mut() {
        create_dir_all(directory)?;
        logger.move_file(directory)?;
    }
    Ok(())
}

pub struct LoggerRef(&'static Mutex<Option<Logger>>);
impl log::Log for LoggerRef {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        self.0.lock().unwrap().as_mut().map(|l| l.log(record));
    }

    fn flush(&self) {
        self.0.lock().unwrap().as_mut().map(|l| l.flush());
    }
}

fn open_log_file(cmd_name: &str) -> Result<(fs::File, PathBuf)> {
    create_dir_all(&*FF_LOG_DIR)?;
    // When using FastFreeze in container mode, logs are opened in this directory,
    // which can be shared with other users. So we make it /tmp like
    let _ = set_tmp_like_permissions(&*FF_LOG_DIR);

    // We pick a random log filename. This is because the log file is saved in the checkpoint
    // image. When we restore, we need to preserve the previous log. Having different log files
    // makes it easier to do so.
    let log_file_path = PathBuf::from(FF_LOG_DIR.join(
        format!("ff-{}-{}-{}.log",
                Utc::now().format("%Y%m%d-%H%M%S"),
                cmd_name,
                &*INVOCATION_ID)));

    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
        .with_context(|| format!("Failed to create log file at {}", log_file_path.display()))?;

    Ok((log_file, log_file_path))
}

pub fn init(level: LevelFilter, cmd_name: &'static str, use_log_file: bool) -> Result<()> {
    // Initializing the logger twice would be a logic error, so it's safe to unwrap().
    log::set_boxed_logger(Box::new(LoggerRef(&LOGGER))).unwrap();
    log::set_max_level(level);

    let log_file = if use_log_file {
        Some(open_log_file(cmd_name)?)
    } else {
        None
    };

    let logger = Logger { cmd_name, log_file, stdout_enabled: false };
    LOGGER.lock().unwrap().replace(logger);

    if use_log_file {
        // We log the time, hostname and invocation ID in the log file, skipping stdout.
        let host = hostname::get().map_or_else(
            |err| format!("<{}>", err),
            |h| h.to_string_lossy().to_string());

        warn!("Time is {}", Utc::now().to_rfc2822());
        warn!("Host is {}", host);
        warn!("Invocation ID is {}", &*INVOCATION_ID);
    }

    LOGGER.lock().unwrap().as_mut().map(|l| l.stdout_enabled = true);

    Ok(())
}
