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

// We have both a lib.rs and main.rs to make writing integration tests possible.
// The integration tests compile to a separate program using this fastfreeze library.

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
