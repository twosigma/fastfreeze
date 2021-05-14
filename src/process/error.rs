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

use std::{
    os::unix::process::ExitStatusExt,
    convert::TryFrom,
    process::ExitStatus,
    fmt,
};

use nix::sys::signal::Signal;
use serde_json::Value;
use crate::util::JsonMerge;
use super::stderr_logger::StderrTail;

#[derive(Debug)]
pub struct ProcessError {
    pub exit_status: ExitStatus,
    pub display_cmd: String,
    pub stderr_tail: Option<StderrTail>,
}

impl ProcessError {
    pub fn to_json(&self) -> Value {
        self.stderr_tail.as_ref().map(|st| json!({
            st.log_prefix.as_ref(): {
                "exit_status": self.formatted_exit_status(),
                "log": &st.tail,
            }
        })).unwrap_or_else(|| json!({}))
    }

    pub fn formatted_exit_status(&self) -> String {
        if let Some(exit_code) = self.exit_status.code() {
            format!("failed with exit_code={}", exit_code)
        } else if let Some(signal) = self.exit_status.signal() {
            let signal = Signal::try_from(signal)
                .map_or_else(|_| format!("signal {}", signal), |s| s.to_string());
            format!("caught fatal {}", signal)
        } else {
            format!("Unexpected child exit status {:?}", self.exit_status)
        }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We don't display the stderr_tail in the error message because it's
        // already on screen. The stderr_tail is used when emitting metrics.
        write!(f, "`{}` {}", self.display_cmd, self.formatted_exit_status())
    }
}

impl std::error::Error for ProcessError {}


#[derive(Debug)]
pub struct ProcessGroupError {
    pub errors: Vec<ProcessError>,
}

impl fmt::Display for ProcessGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.errors.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", "))
    }
}

impl std::error::Error for ProcessGroupError {}

impl ProcessGroupError {
    pub fn to_json(&self) -> Value {
        self.errors.iter()
            .map(|e| e.to_json())
            .fold(json!({}), |a,b| a.merge(b))
    }
}
