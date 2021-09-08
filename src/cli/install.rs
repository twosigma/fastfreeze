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
use nix::{
    Error,
    errno::Errno,
    sys::stat::stat,
};
use crate::{
    consts::*,
    util::{create_dir_all, atomic_symlink, copy_file, copy_lib, set_tmp_like_permissions},
    container,
};


/// Install FastFreeze, required when namespaces are not available (e.g., Docker).
#[derive(StructOpt, PartialEq, Debug, Serialize)]
pub struct Install {
    /// Verbosity. Can be repeated
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,

    /// Proceed with installation, even if containers can be created, and
    /// installation would not be necessary.
    #[structopt(long)]
    pub force: bool,

    /// Skip the ELF loader hijacking. This is typically done when using a
    /// container image that cannot be modified. The install command is run in
    /// an k8s init container, and a volume mount is used to hijack the ELF
    /// loader.
    #[structopt(long)]
    pub skip_elf_hijacking: bool,
}

/// Returns whether we have hijacked the ELF loader
pub fn is_ff_installed() -> Result<bool> {
    // Comparing file inodes between the system loader and the virtcpuid tells
    // us if the system loader is in fact the virtcpuid loader in the following
    // installation methods: 1) symlink 2) hardlinks 3) and mount binds.
    // It doesn't cover the case where one would copy the content of the
    // virtcpuid loader onto the system loader, but that's fine, we don't expect
    // users to do that.
    // Note: lstat() doesn't follow symlinks, but stat() does.

    let ld_virtcpuid_stat = match stat(&*LD_VIRTCPUID_PATH) {
        Ok(s) => s,
        Err(Error::Sys(Errno::ENOENT)) => return Ok(false),
        Err(e) => bail!("Failed to stat {}: {}", LD_VIRTCPUID_PATH.display(), e),
    };

    let ld_system_stat = stat(&*LD_SYSTEM_PATH)
        .with_context(|| format!("Failed to stat {}", LD_SYSTEM_PATH.display()))?;

    Ok(
        ld_system_stat.st_dev == ld_virtcpuid_stat.st_dev &&
        ld_system_stat.st_ino == ld_virtcpuid_stat.st_ino
    )
}

pub fn prepare_ff_dir() -> Result<()> {
    // NO_PRESERVE_FF_DIR includes FF_DIR in its subpath. One stone two birds.
    create_dir_all(&*NO_PRESERVE_FF_DIR)?;
    // We want to give the application a /tmp that we'll include in our image,
    create_dir_all(&*CONTAINER_APP_TMP)?;

    // We might be root, so we give /tmp-like permissions to allow other users
    // to write to the directory But this can fail. We can get an EPERM error if
    // FF_DIR is volume-bind mounted for example. If chmod fails, that's fine,
    // but FastFreeze can only be ran as the user who installed fastfreeze.
    if let Err(e) = set_tmp_like_permissions(&*FF_DIR)
                .and(set_tmp_like_permissions(&*NO_PRESERVE_FF_DIR))
                .and(set_tmp_like_permissions(&*CONTAINER_APP_TMP)) {
        warn!("{}\nThat's okay. \
                The only restriction is to not change user (uid) when using FastFreeze", e);
    }

    // Preparing these library files may not be necessary. For example, when we
    // have time namespaces, and no CPUID to virtualize, we don't need any of
    // these. However, we could be restoring a checkpoint image that was started
    // on a machine that didn't have such time namespace. That restore operation
    // will need these files. Note that these files are not included in the
    // checkpoint image.
    copy_file(&*LD_SYSTEM_PATH, &*LD_SYSTEM_ORIG_PATH)?;
    copy_lib(&*LD_VIRTCPUID_PATH)?;
    copy_lib(&*LIBVIRTCPUID_PATH)?;
    copy_lib(&*LIBVIRTTIME_PATH)?;

    Ok(())
}

impl super::CLI for Install {
    fn run(self) -> Result<()> {
        let Self { verbose: _, force, skip_elf_hijacking } = self;

        ensure!(!is_ff_installed()?, "FastFreeze is already installed (the ELF loader is already hijacked)");

        match (container::Privileges::detect()?.can_mount_bind, force) {
            (false, _) => {}
            (true, false) => bail!(
                "Installation does not seem necessary because FastFreeze can create mount namespaces. \
                 Use `--force` if you want to proceed. Use it when building Docker images that are meant to run in restricted environment."),
            (true, true) => warn!("Installation does not seem necessary, but proceeding anyways"),
        }

        prepare_ff_dir()?;

        if skip_elf_hijacking {
            warn!("Installation is partially complete: a volume mount is needed to interpose the system ELF loader. \
                   Ask the FastFreeze team for details on how to do so");
        } else {
            // symlink /var/tmp/fastfreeze/run/ld-virtcpuid.so to /lib/ld-linux.so
            atomic_symlink(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH)
                .context("The ELF loader cannot be hijacked. You may try to use --skip-elf-hijacking")?;
        }

        Ok(())
    }
}
