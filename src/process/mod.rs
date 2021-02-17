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

mod command;
mod process_group;
mod process;
mod spawn_with_pid;
mod stderr_logger;
mod error;
mod monitor;

pub use command::{Command, PipeCommandExt, Stdio, EnvVars};
pub use process::{Process, Output};
pub use process_group::{ProcessExt, ProcessGroup};
pub use error::{ProcessError, ProcessGroupError};
pub use spawn_with_pid::{CommandPidExt, set_ns_last_pid, spawn_set_ns_last_pid_server, MIN_PID};
pub use monitor::{monitor_child, ChildDied};
