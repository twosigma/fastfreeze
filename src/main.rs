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

pub mod logger;
pub mod util;
pub mod process;
pub mod cli;
pub mod store;
pub mod image;
pub mod virt;
pub mod metrics;
pub mod consts;
pub mod criu;
pub mod filesystem;
pub mod image_streamer;
pub mod lock;
pub mod signal;

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_json;

use anyhow::Result;
use structopt::StructOpt;

use crate::{
    consts::*,
    cli::{ExitCode, CLI},
    virt::disable_local_time_virtualization,
    signal::trap_sigterm_and_friends,
};

fn main() {
    fn do_main() -> Result<()> {
        // We have to be exempt from time virtualization because we use
        // `Instant::now()`, which uses CLOCK_MONOTONIC.
        // disable_local_time_virtualization() does an execve() if needed.
        disable_local_time_virtualization()?;

        // START_TIME is used for logging purposes
        lazy_static::initialize(&START_TIME);

        // Trapping signals is important for cleanups (e.g., kill children) before we exit
        trap_sigterm_and_friends()?;

        let opts = cli::Opts::from_args();
        opts.init_logger();
        opts.run()
    }

    if let Err(e) = do_main() {
        log::error!("{:#}", e);
        let exit_code = ExitCode::from_error(&e);
        std::process::exit(exit_code as i32);
    }
}
