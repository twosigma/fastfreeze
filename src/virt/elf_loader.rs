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
use std::{
    io::prelude::*,
    io::{BufRead, BufReader, BufWriter, Cursor},
    os::unix::ffi::OsStrExt,
    env,
    fs,
};
use crate::{
    consts::*,
    process::{Command, Stdio, EnvVars},
    container,
    virt,
};

fn get_virtualization_envvars(config: &virt::Config) -> EnvVars {
    let mut env: EnvVars = EnvVars::new();
    let mut ld_preloads = vec![];

    if config.use_libvirttime() {
        ld_preloads.push(LIBVIRTTIME_PATH.clone());
        env.insert("VIRT_TIME_CONF".into(), (&*VIRT_TIME_CONF_PATH).into());
    }

    if let Some(ref cpuid_mask) = config.cpuid_mask {
        ld_preloads.push(LIBVIRTCPUID_PATH.clone());
        env.insert("VIRT_CPUID_MASK".into(), cpuid_mask.into());
    }

    // Users can force env variables via FF_APP_INJECT_*
    for (key, value) in config.ff_app_inject_vars.iter() {
        if key == "LD_PRELOAD" {
            for path in env::split_paths(&value) {
                ld_preloads.push(path);
            }
        } else {
            env.insert(key.into(), value.into());
        }
    }

    // unwrap is okay here as we cannot possibly have a ":" in one of the ld_preload paths.
    env.insert("LD_PRELOAD".into(), env::join_paths(ld_preloads).unwrap());

    // Giving something to look for to ensure_elf_loader_working()
    env.insert("FF_ELF_LOADER".into(), "1".into());

    env
}

/// The system ELF loader interposition loads the LD_INJECT_ENV_PATH as
/// environment variable for all application on the system.
pub fn configure_elf_loader(config: &virt::Config) -> Result<()> {
    let env = get_virtualization_envvars(config);

    trace!("Writing ELF loader config: {:#?}", env);

    || -> Result<_> {
        // These env variables are forced into any program
        // that do not have LD_ENV_DISABLE enabled.
        let mut ld_inject_file = BufWriter::new(
            fs::File::create(&*LD_INJECT_ENV_PATH)?);

        for (key, value) in env {
            // format!() would be nicer, but we need to work with OsString, not String.
            ld_inject_file.write_all(key.as_bytes())?;
            ld_inject_file.write_all(b"=")?;
            ld_inject_file.write_all(value.as_bytes())?;
            ld_inject_file.write_all(b"\n")?;
        }

        ld_inject_file.flush()?;

        Ok(())
    }().with_context(|| format!("Failed to create {}", LD_INJECT_ENV_PATH.display()))
}

fn ensure_elf_loader_working() -> Result<()> {
    // Check if new processes are getting the env variables from
    // get_virtualization_envvars() via the ELF loader.
    // We fork+execve `env` and see if FF_ELF_LOADER shows up even
    // though we unset it in our environment.
    env::remove_var("FF_ELF_LOADER");

    let output = || -> Result<_> {
        Command::new(&["env"])
            .stdout(Stdio::piped())
            .spawn()?
            .wait_with_output()
            .and_then(|o| o.ensure_success().map(|_| o))
    }().context("Failed to run the `env` command after configuring the ELF loader")?;

    for line in BufReader::new(Cursor::new(output.stdout)).lines() {
        let line = line.unwrap_or_default();
        if line.starts_with("FF_ELF_LOADER=") {
            return Ok(());
        }
    }

    bail!("The ELF loader is not injecting env variables as expected");
}

pub fn hijack_elf_loader(config: &virt::Config) -> Result<()> {
    if config.hijack_elf_loader_via_ff_install() {
        // no hijacking to do, `ff install` has already been done and symlinked the loader.
        ensure_elf_loader_working()?;
    } else if config.hijack_elf_loader_via_mount_bind() {
        container::mount_bind(&*LD_VIRTCPUID_PATH, &*LD_SYSTEM_PATH)?;
        ensure_elf_loader_working()?;
    }

    Ok(())
}

/// This function is called early on to disable the system wide time
/// virtualization on our process as we need the non-virt time in time.rs.
/// XXX This function can call execve(). Note that logging is not setup yet.
/// This can be taken out once we remove userspace time virtualization.
pub fn disable_local_time_virtualization() -> Result<()> {
    if env::var_os("VIRT_TIME_CONF").is_some() {
        // We are currently executing with time virtualization enabled. This is
        // a problem when we try to get the real machine clock. To avoid this,
        // we re-exec ourselves with LD_ENV_DISABLE set, which prevents the
        // libvirtcpuid's loader from injecting env variables into our process.
        env::set_var("LD_ENV_DISABLE", "1");
        env::remove_var("VIRT_TIME_CONF");
        env::remove_var("LD_PRELOAD"); // libvirttime.so is in there, and needs to go.

        Command::new(env::args_os())
            .exec()
            .context("Failed to execve() ourselves to disable time virtualization")
    } else {
        // We are not virtualized, but our children should be.
        env::remove_var("LD_ENV_DISABLE");
        Ok(())
    }
}
