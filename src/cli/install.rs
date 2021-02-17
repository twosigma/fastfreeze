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
use structopt::StructOpt;
use serde::Serialize;
use std::io::ErrorKind;
use crate::{
    consts::*,
    util::{create_dir_all, find_lib, atomic_symlink, copy_file, set_tmp_like_permissions},
    container,
};

/// Install FastFreeze, mostly to setup virtualization
#[derive(StructOpt, PartialEq, Debug, Serialize)]
pub struct Install {
    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Proceed with installation, even if containers can be created, and
    /// installation would not be necessary.
    #[structopt(long)]
    pub force: bool,
}

pub fn is_ff_installed() -> Result<bool> {
    Ok(match LD_SYSTEM_PATH.read_link() {
        Ok(path) => path.to_string_lossy().contains("virtcpuid"),
        // EINVAL means the file is not a symlink.
        Err(e) if e.kind() == ErrorKind::InvalidInput => false,
        Err(e) => Err(e).with_context(||
            format!("Failed to read link {}", LD_SYSTEM_PATH.display()))?,
    })
}

pub fn prepare_ff_dir() -> Result<()> {
    create_dir_all(&*NO_PRESERVE_FF_DIR)?; // Includes FF_DIR in its subpath.

    // We give /tmp-like permissions to allow other users to write to the directory
    // But this can fail. We can get an EPERM error if FF_DIR is volume-bind mounted for
    // example. If chmod fails, that's fine, but fastfreeze can only be ran as the user who
    // installed fastfreeze.
    if let Err(e) = set_tmp_like_permissions(&*FF_DIR)
                .and(set_tmp_like_permissions(&*NO_PRESERVE_FF_DIR)) {
        warn!("{}\nThat's okay. \
                The only restriction is to not change user (uid) when using fastfreeze", e);
    }

    // copy /lib/ld-linux.so to /var/tmp/fastfreeze/run/ld-linux.so
    copy_file(&*LD_SYSTEM_PATH, &*LD_SYSTEM_ORIG_PATH)?;

    // copy our virtualization libraries to /var/tmp/fastfreeze/run/
    for path in &[&*LD_VIRTCPUID_PATH, &*LIBVIRTCPUID_PATH, &*LIBVIRTTIME_PATH] {
        copy_file(find_lib(path.file_name().unwrap())?, path)?;
    }

    Ok(())
}

impl super::CLI for Install {
    fn run(self) -> Result<()> {
        let Self { verbose: _, force } = self;

        match (container::ns_capabilities()?.can_mount_ns(), force) {
            (false, _) => {}
            (true, false) => bail!(
                "Installation does not seem necessary because FastFreeze can create mount namespaces. \
                 Use `--force` if you want to proceed. Use it when building Docker images that are meant to run in restricted environment."),
            (true, true) => warn!("Installation does not seem necessary, but proceeding anyways"),
        }

        prepare_ff_dir()?;

        // symlink /var/tmp/fastfreeze/run/ld-virtcpuid.so to /lib/ld-linux.so
        if let Err(_) = atomic_symlink(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH) {
            warn!("Installation is partial. A volume mount is \
                   needed to interpose the system ELF loader {}. \
                   See the kubernetes yaml example for details on how to do so", LD_SYSTEM_PATH.display());
        } else {
            info!("Installation is complete");
        }

        Ok(())
    }
}
