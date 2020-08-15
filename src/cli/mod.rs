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

mod run;
mod checkpoint;
mod extract;
mod wait;
mod install;
mod main;

pub trait CLI {
    fn run(self) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub struct ExitCode(pub u8);
impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Exiting with exit_code={}", self.0)
    }
}

impl ExitCode {
    pub fn from_error(e: &anyhow::Error) -> Option<u8> {
        e.downcast_ref::<Self>().map(|exit_code| exit_code.0)
    }
}

pub use main::Opts;
