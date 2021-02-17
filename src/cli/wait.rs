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
use std::time::{Instant, Duration};
use structopt::StructOpt;
use serde::Serialize;
use crate::{
    container,
    lock::checkpoint_restore_lock,
};


/// Wait for checkpoint or restore to finish
#[derive(StructOpt, PartialEq, Debug, Serialize)]
pub struct Wait {
    /// Fail after some specified number of seconds. Decimals are allowed
    #[structopt(short, long)]
    timeout: Option<f64>,

    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Target the specified application. See the run command help about
    /// --app-name for more details.
    #[structopt()]
    app_name: Option<String>,
}

impl super::CLI for Wait {
    fn run(self) -> Result<()> {
        let Self { timeout, app_name, verbose: _ } = self;
        let timeout = timeout.map(|t| Instant::now() + Duration::from_secs_f64(t));

        container::enter_app_namespace(app_name.as_ref())?;

        let _lock_guard = checkpoint_restore_lock(timeout, false)?;
        Ok(())
    }
}
