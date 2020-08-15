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
    io::prelude::*,
    io::stderr,
    sync::Mutex,
    fs,
};
use log::{Record, Metadata};
pub use log::LevelFilter;
use chrono::prelude::*;
use crate::{
    consts::*,
    util::create_dir_all,
};


pub struct Logger {
    cmd_name: &'static str,
    log_file: Option<Mutex<fs::File>>,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let msg = format!("[ff.{}] ({:.3}s) {}\n",
            self.cmd_name, START_TIME.elapsed().as_secs_f64(), record.args());

        // When writing our log outputs fail, we dismiss the errors.
        // Maybe there's something better to do.
        let _ = stderr().write_all(msg.as_bytes());
        let _ = self.log_file.as_ref().map(|f|
            f.lock().unwrap().write_all(msg.as_bytes()));
    }

    fn flush(&self) {
        let _ = stderr().flush();
        let _ = self.log_file.as_ref().map(|f|
            f.lock().unwrap().flush());
    }
}

fn open_log_file(cmd_name: &str) -> Result<fs::File> {
    create_dir_all(&*FF_LOG_DIR)?;

    // We pick a random log filename. This is because the log file is saved in the checkpoint
    // image. When we restore, we need to preserve the previous log. Having different log files
    // makes it easier to do so.
    let log_file = FF_LOG_DIR.join(
        format!("ff-{}-{}-{}.log",
                Utc::now().format("%Y%m%d-%H%M%S"),
                cmd_name,
                &*INVOCATION_ID));

    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?)
}

pub fn init(level: LevelFilter, cmd_name: &'static str, use_log_file: bool) {
    let (log_file, log_file_error) = if use_log_file {
        // If we can't open the log file, we can't report the failure yet
        // as the logger is not yet initialized. So we stash the error,
        // and log it later.
        match open_log_file(cmd_name) {
            Ok(f) => (Some(f), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };

    let log_file = log_file.map(Mutex::new);
    let logger = Logger { cmd_name, log_file };

    // An error is returned when the logger has already been initialized.
    // Initializing the logger twice would be a logic error, so it's safe to unwrap().
    log::set_boxed_logger(Box::new(logger)).unwrap();
    log::set_max_level(level);

    if let Some(err) = log_file_error {
        warn!("WARN: Failed to open the log file at {}: {}",
              FF_LOG_DIR.display(), err);
    }

    if use_log_file {
        let host = hostname::get().map_or_else(
            |err| format!("<{}>", err),
            |h| h.to_string_lossy().to_string());

        warn!("Time is {}", Utc::now().to_rfc2822());
        warn!("Host is {}", host);
        warn!("Invocation ID is {}", &*INVOCATION_ID);
    }
}
