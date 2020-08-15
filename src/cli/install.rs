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
use crate::{
    consts::*,
    util::{create_dir_all, find_lib, atomic_symlink, copy_file},
};

use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
};

/// Install FastFreeze, mostly to setup virtualization
#[derive(StructOpt, PartialEq, Debug, Serialize)]
pub struct Install {
    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}

impl super::CLI for Install {
    fn run(self) -> Result<()> {
        if let Err(_) = create_dir_all(&*FF_DIR) {
            bail!("{} should be volume mounted. See the kubernetes yaml example. \
                   It is used for interposing the system ELF loader", FF_DIR.display());
        }
        create_dir_all(&*NO_PRESERVE_FF_DIR)?;

        // We give /tmp-like permissions to allow other users to write to the directory
        fs::set_permissions(&*FF_DIR, Permissions::from_mode(0o1777))?;
        fs::set_permissions(&*NO_PRESERVE_FF_DIR, Permissions::from_mode(0o1777))?;

        let system_ld_real_path = LD_SYSTEM_PATH.read_link()
            .with_context(|| format!("Failed to read link {}", LD_SYSTEM_PATH.display()))?;

        if system_ld_real_path.to_string_lossy().contains("virtcpuid") {
            warn!("Installation is already done, skipping");
            return Ok(());
        }

        // copy /lib/ld-linux.so to /var/fastfreeze/run/ld-linux.so
        copy_file(system_ld_real_path, &*LD_SYSTEM_ORIG_PATH)?;

        // copy our virtualization libraries to /var/fastfreeze/run/
        for path in &[&*LD_VIRTCPUID_PATH, &*LIBVIRTCPUID_PATH, &*LIBVIRTTIME_PATH] {
            copy_file(find_lib(path.file_name().unwrap())?, path)?;
        }

        // symlink /var/fastfreeze/run/ld-virtcpuid.so to /lib/ld-linux.so
        if let Err(_) = atomic_symlink(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH) {
            warn!("Installation is complete, but a kubernetes volume mount is \
                   needed to interpose the system ELF loader {}. \
                   See the kubernetes yaml example for details on how to do so", LD_SYSTEM_PATH.display());
        } else {
            info!("Installation is complete");
        }

        Ok(())
    }
}
