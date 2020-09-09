
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
    path::PathBuf,
    collections::HashSet,
    fs,
};
use crate::{
    consts::*,
    process::{Command, Process, Stdio},
};

lazy_static! {
    static ref TAR_CMD: String = std::env::var("TAR_CMD")
        .unwrap_or_else(|_| "tar".to_string());
}

pub fn spawn_tar(preserved_paths: HashSet<PathBuf>, stdout: fs::File) -> Result<Process> {
    let mut cmd = Command::new(&[&*TAR_CMD]);
    if log_enabled!(log::Level::Trace) {
        cmd.arg("--verbose");
    }
    cmd.args(&[
        "--directory", "/",
        "--create",
        "--preserve-permissions",
        "--ignore-failed-read", // Allows us to discard EPERM errors of files in /tmp
        "--sparse", // Support sparse files efficiently, libvirttime uses one
        "--file", "-",
    ])
        .arg("--exclude").arg(&*NO_PRESERVE_FF_DIR)
        .args(&preserved_paths)
        .arg(&*FF_DIR)
        .stdout(Stdio::from(stdout))
        .spawn()
}

pub fn spawn_untar(stdin: fs::File) -> Result<Process> {
    let mut cmd = Command::new(&[&*TAR_CMD]);
    if log_enabled!(log::Level::Trace) {
        cmd.arg("--verbose");
    }
    cmd.args(&[
        "--directory", "/",
        "--extract",
        "--preserve-permissions",
        "--no-overwrite-dir",
        "--file", "-",
    ])
        .stdin(Stdio::from(stdin))
        .spawn()
}
