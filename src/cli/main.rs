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
use structopt::{StructOpt, clap::AppSettings};
use serde::Serialize;
use crate::logger;
use super::{
    CLI,
    checkpoint::Checkpoint,
    extract::Extract,
    install::Install,
    run::Run,
    wait::Wait,
};

#[derive(StructOpt, PartialEq, Debug, Serialize)]
#[structopt(
    // When showing --help, we want to keep the order of arguments as we defined,
    // as opposed to the default alphabetical order.
    global_setting(AppSettings::DeriveDisplayOrder),
    // help subcommand is not useful, disable it.
    global_setting(AppSettings::DisableHelpSubcommand),
    // subcommand version is not useful, disable it.
    global_setting(AppSettings::VersionlessSubcommands),
)]
#[structopt(after_help("    restore-only is achived by using \
the `run` subcommand without passing the application command-line arguments"
))]
pub struct Opts {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, PartialEq, Debug, Serialize)]
enum Command {
    Run(Run),
    Checkpoint(Checkpoint),
    Extract(Extract),
    Wait(Wait),
    Install(Install),
}

impl Opts {
    // It looks a bit silly not to have a global verbose option flag, but if we
    // use a global flag, then the user _must_ pass --verbose before the
    // subcommand, which is even more silly.
    // clap should be better
    fn verbosity(&self) -> u8 {
        match self.command {
            Command::Install(Install { verbose, .. }) |
            Command::Run(Run { verbose, .. }) |
            Command::Checkpoint(Checkpoint { verbose, .. }) |
            Command::Extract(Extract { verbose, .. }) |
            Command::Wait(Wait { verbose, .. }) => verbose,
        }
    }

    fn log_level(&self) -> logger::LevelFilter {
        match self.verbosity() {
            0 => logger::LevelFilter::Info,
            1 => logger::LevelFilter::Debug,
            _ => logger::LevelFilter::Trace,
        }
    }

    fn log_prefix(&self) -> &'static str {
        match self.command {
            Command::Install(_)    => "install",
            Command::Run(_)        => "run",
            Command::Checkpoint(_) => "checkpoint",
            Command::Extract(_)    => "extract",
            Command::Wait(_)       => "wait",
        }
    }

    fn use_log_file(&self) -> bool {
        // Persisting a log file is helpful to carry the history of the
        // application in the checkpointed image.
        matches!(self.command,
            Command::Run(_) |
            Command::Checkpoint(_)
        )
    }

    pub fn init_logger(&self) -> Result<()> {
        logger::init(self.log_level(), self.log_prefix(), self.use_log_file())
    }
}

impl CLI for Opts {
    fn run(self) -> Result<()> {
        match self.command {
            Command::Install(opts)    => opts.run(),
            Command::Run(opts)        => opts.run(),
            Command::Checkpoint(opts) => opts.run(),
            Command::Extract(opts)    => opts.run(),
            Command::Wait(opts)       => opts.run(),
        }
    }
}
